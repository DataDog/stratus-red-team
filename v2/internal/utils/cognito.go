package utils

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// This file implements the client side of the AWS Cognito SRP (Secure Remote Password)
// authentication flow (USER_SRP_AUTH). It allows detonation code to authenticate to a
// Cognito user pool the same way standard tooling does (e.g. the AWS Amplify SDK or the
// pycognito Python library), producing the InitiateAuth -> RespondToAuthChallenge API
// call sequence that matches real-world attacker behavior.
//
// The protocol follows RFC 5054 with the parameters AWS uses: the RFC 3526 3072-bit MODP
// group and generator g = 2. Reference implementation: https://github.com/capless/warrant

const (
	// srpNHex is the RFC 3526 3072-bit MODP group prime used by AWS Cognito.
	srpNHex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
		"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
		"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
		"83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
		"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
		"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
		"DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
		"15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64" +
		"ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" +
		"ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B" +
		"F12FFA06D98A0864D87602733EC86A64521F2B18177B200C" +
		"BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31" +
		"43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"
	srpInfoBits = "Caldera Derived Key"
)

// CognitoSrpClient holds the client-side SRP state for a single authentication attempt.
type CognitoSrpClient struct {
	poolName  string // the part of the user pool ID after the underscore (e.g. "abcd1234")
	bigN      *big.Int
	g         *big.Int
	k         *big.Int
	smallA    *big.Int
	largeAHex string
}

// NewCognitoSrpClient creates an SRP client for the given user pool and generates the
// client's ephemeral key pair (a, A). userPoolId is of the form "<region>_<id>".
func NewCognitoSrpClient(userPoolId string) (*CognitoSrpClient, error) {
	parts := strings.SplitN(userPoolId, "_", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid user pool ID %q, expected format <region>_<id>", userPoolId)
	}

	bigN, _ := new(big.Int).SetString(srpNHex, 16)
	g := big.NewInt(2)
	k := hexToBig(hexHash(padHex(bigToHex(bigN)) + padHex(bigToHex(g))))

	client := &CognitoSrpClient{poolName: parts[1], bigN: bigN, g: g, k: k}
	if err := client.generateKeyPair(); err != nil {
		return nil, err
	}
	return client, nil
}

// generateKeyPair picks a random secret a and computes A = g^a mod N, ensuring A mod N != 0.
func (c *CognitoSrpClient) generateKeyPair() error {
	for attempt := 0; attempt < 10; attempt++ {
		randomBytes := make([]byte, 128)
		if _, err := rand.Read(randomBytes); err != nil {
			return fmt.Errorf("failed to generate SRP random value: %w", err)
		}
		smallA := new(big.Int).Mod(new(big.Int).SetBytes(randomBytes), c.bigN)
		largeA := new(big.Int).Exp(c.g, smallA, c.bigN)
		if new(big.Int).Mod(largeA, c.bigN).Sign() != 0 {
			c.smallA = smallA
			c.largeAHex = bigToHex(largeA)
			return nil
		}
	}
	return fmt.Errorf("failed to generate a valid SRP key pair")
}

// InitiateAuthParameters returns the AuthParameters to pass to the InitiateAuth API call
// for the USER_SRP_AUTH flow.
func (c *CognitoSrpClient) InitiateAuthParameters(username string) map[string]string {
	return map[string]string{
		"USERNAME": username,
		"SRP_A":    c.largeAHex,
	}
}

// PasswordVerifierChallengeResponses computes the response to the PASSWORD_VERIFIER
// challenge returned by InitiateAuth. The returned map is passed as ChallengeResponses to
// the RespondToAuthChallenge API call.
func (c *CognitoSrpClient) PasswordVerifierChallengeResponses(challengeParams map[string]string, password string) (map[string]string, error) {
	userIdForSrp := challengeParams["USER_ID_FOR_SRP"]
	saltHex := challengeParams["SALT"]
	srpBHex := challengeParams["SRP_B"]
	secretBlock := challengeParams["SECRET_BLOCK"]
	if userIdForSrp == "" || saltHex == "" || srpBHex == "" || secretBlock == "" {
		return nil, fmt.Errorf("missing expected SRP challenge parameters in server response")
	}

	bigB := hexToBig(srpBHex)
	if new(big.Int).Mod(bigB, c.bigN).Sign() == 0 {
		return nil, fmt.Errorf("invalid server SRP value B (B mod N == 0)")
	}

	key := c.derivePasswordAuthenticationKey(userIdForSrp, password, bigB, saltHex)

	timestamp := time.Now().UTC().Format("Mon Jan 2 15:04:05 MST 2006")
	secretBlockBytes, err := base64.StdEncoding.DecodeString(secretBlock)
	if err != nil {
		return nil, fmt.Errorf("failed to decode SRP secret block: %w", err)
	}

	var message []byte
	message = append(message, []byte(c.poolName)...)
	message = append(message, []byte(userIdForSrp)...)
	message = append(message, secretBlockBytes...)
	message = append(message, []byte(timestamp)...)
	signature := base64.StdEncoding.EncodeToString(hmacSHA256(key, message))

	return map[string]string{
		"USERNAME":                    userIdForSrp,
		"TIMESTAMP":                   timestamp,
		"PASSWORD_CLAIM_SECRET_BLOCK": secretBlock,
		"PASSWORD_CLAIM_SIGNATURE":    signature,
	}, nil
}

// derivePasswordAuthenticationKey computes the shared SRP session key used to sign the
// password claim, following the Cognito variant of the SRP protocol.
func (c *CognitoSrpClient) derivePasswordAuthenticationKey(username, password string, bigB *big.Int, saltHex string) []byte {
	u := hexToBig(hexHash(padHex(c.largeAHex) + padHex(bigToHex(bigB))))

	usernamePasswordHash := hashSHA256([]byte(c.poolName + username + ":" + password))
	x := hexToBig(hexHash(padHex(saltHex) + usernamePasswordHash))

	// s = (B - k * g^x)^(a + u*x) mod N
	gModPowX := new(big.Int).Exp(c.g, x, c.bigN)
	base := new(big.Int).Sub(bigB, new(big.Int).Mul(c.k, gModPowX))
	base.Mod(base, c.bigN) // Euclidean mod yields a non-negative result in [0, N)
	exponent := new(big.Int).Add(c.smallA, new(big.Int).Mul(u, x))
	s := new(big.Int).Exp(base, exponent, c.bigN)

	return computeHKDF(padHexBytes(s), padHexBytes(u))
}

// computeHKDF performs the single-block HKDF (extract + one expand) that Cognito uses to
// derive a 16-byte key.
func computeHKDF(ikm, salt []byte) []byte {
	prk := hmacSHA256(salt, ikm)
	info := append([]byte(srpInfoBits), byte(1))
	return hmacSHA256(prk, info)[:16]
}

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// hashSHA256 returns the hex-encoded SHA-256 digest of the given bytes.
func hashSHA256(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

// hexHash decodes a hex string to bytes and returns the hex-encoded SHA-256 digest.
func hexHash(hexStr string) string {
	decoded, _ := hex.DecodeString(hexStr)
	return hashSHA256(decoded)
}

func hexToBig(hexStr string) *big.Int {
	value, _ := new(big.Int).SetString(hexStr, 16)
	return value
}

func bigToHex(value *big.Int) string {
	return fmt.Sprintf("%x", value)
}

func padHexBytes(value *big.Int) []byte {
	decoded, _ := hex.DecodeString(padHex(bigToHex(value)))
	return decoded
}

// padHex left-pads a hex string so it is interpreted as an unsigned value with an even
// number of digits, matching the reference SRP implementation.
func padHex(hexStr string) string {
	if len(hexStr)%2 == 1 {
		return "0" + hexStr
	}
	if strings.IndexByte("89abcdefABCDEF", hexStr[0]) != -1 {
		return "00" + hexStr
	}
	return hexStr
}
