terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.0"
    }
  }
}
provider "aws" {
  skip_region_validation      = true
  skip_credentials_validation = true
  skip_get_ec2_platforms      = true
}

resource "random_string" "suffix" {
  length    = 6
  min_lower = 6
  special   = false
}

locals {
  resource_prefix = "stratus-red-team-ransomware-bucket"
  bucket_name     = format("%s-%s", local.resource_prefix, random_string.suffix.result)
  num-files       = 51
  min-size-bytes  = 1
  max-size-bytes  = 200
  file-extensions = ["sql", "txt", "docx", "pdf", "png", "tar.gz"]
  wordlist = split("\n", <<EOW
liable
donated
mayday
blooper
pueblo
tantrum
scary
secret
secluded
babied
ignition
unfasten
affirm
margarine
credit
underage
june
licking
approve
overbite
ditto
pavilion
chewy
drivable
favorable
kitchen
wriggly
shape
resistant
unless
backlight
cruelty
empower
freewill
passage
net
retrial
hulk
drizzly
ambitious
banknote
calm
these
outlet
survivor
silenced
fantasy
flogging
aeration
balsamic
antivirus
glowing
setup
unpopular
immobile
divisive
dosage
amicably
follicle
ogle
subscribe
second
mountable
catnap
yummy
frill
take
challenge
voyage
chevy
caravan
busload
boss
irk
selection
surreal
gliding
preset
dastardly
curliness
colossal
litigate
phony
hardly
connected
waviness
capital
carefully
obstruct
carton
rebuttal
underfeed
aqueduct
chomp
kindle
outfield
niece
consult
truth
gloomy
shiftless
robust
hypnotic
stricken
vaguely
buckle
galore
unheard
slum
marathon
portfolio
anchor
prodigy
bonelike
tamper
sharper
chair
hardhead
overfill
lyrically
erratic
schilling
reveler
tabloid
guise
sulfate
activism
lecturer
nanny
overnight
diligent
knelt
refutable
dotted
cosigner
wife
appliance
plutonium
defiant
iphone
outreach
abroad
yoga
singular
uncombed
feline
python
crabbing
sixtieth
gag
erupt
squeegee
juvenile
usher
specked
septum
reissue
fox
undiluted
tattling
conch
hypocrisy
flashy
thousand
gilled
wager
sandbag
crinkle
among
bulb
craving
willing
sincerity
surfer
elated
relapse
moonstone
treading
curse
appease
germinate
crablike
synopsis
snowdrop
railcar
broom
repeal
drastic
ritzy
dexterous
rut
numerous
wiring
scorpion
gorged
clumsy
cognitive
scoured
dirtiness
designer
dealing
unrigged
obsessive
onyx
tweed
unsubtly
brook
overrate
egotistic
mower
coeditor
unexpired
chip
acclaim
copied
uneasy
rope
unrivaled
unchanged
uncross
camcorder
thigh
aerospace
pouring
dullness
trickster
isolation
revert
purse
unsuited
frightful
sardine
output
poem
handgun
ribbon
consumer
nutcase
catapult
happily
jubilant
selected
blasphemy
unwed
sludge
distrust
bullpen
coronary
tactile
abiding
eradicate
exclude
deniable
overcast
deputize
glider
bondless
embark
blunt
dropbox
riveting
outflank
cactus
onlooker
decimeter
slip
treat
decrease
throat
cobalt
freebee
spring
contusion
compacted
exciting
paging
bulginess
decade
precise
swooned
overbid
stream
fried
recount
dad
falcon
ajar
art
twisted
cesarean
handheld
tractor
gulp
unlatch
sandpit
sitcom
shout
singing
subheader
unvarying
EOW
  )
}

resource "aws_s3_bucket" "bucket" {
  bucket = local.bucket_name

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
  force_destroy = true
}

resource "aws_s3_bucket_versioning" "bucket" {
  bucket = aws_s3_bucket.bucket.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "random_integer" "fake-objects-size" {
  count = local.num-files
  min   = local.min-size-bytes
  max   = local.max-size-bytes
}

resource "random_id" "fake-objects-content" {
  count       = local.num-files
  byte_length = random_integer.fake-objects-size[count.index].result
}

resource "random_shuffle" "fake-objects-names" {
  count        = local.num-files
  input        = local.wordlist
  result_count = 2
}

resource "random_shuffle" "fake-objects-extensions" {
  count        = local.num-files
  input        = local.file-extensions
  result_count = 1
}

resource "random_shuffle" "fake-objects-name-separators" {
  count        = local.num-files
  input        = [" ", "-", "_"]
  result_count = 1
}

resource "aws_s3_bucket_object" "fake-objects" {
  count   = local.num-files
  bucket  = aws_s3_bucket.bucket.id
  key     = format("%s.%s", join(random_shuffle.fake-objects-name-separators[count.index].result[0], random_shuffle.fake-objects-names[count.index].result), random_shuffle.fake-objects-extensions[count.index].result[0])
  content = random_id.fake-objects-content[count.index].hex

  depends_on = [aws_s3_bucket_versioning.bucket] # Make sure versioning is enabled before objects are uploaded
}

output "display" {
  value = format("S3 bucket %s containing %d fake objects ready", aws_s3_bucket.bucket.id, local.num-files)
}

output "bucket_name" {
  value = aws_s3_bucket.bucket.id
}