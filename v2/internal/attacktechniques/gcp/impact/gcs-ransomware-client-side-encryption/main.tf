terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.18.1"
    }
  }
}

resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

locals {
  resource_prefix = "stratus-red-team-ransomware-bucket"
  bucket_name     = format("%s-%s", local.resource_prefix, random_string.suffix.result)
  num_files       = 51
  min_size_bytes  = 1
  max_size_bytes  = 200
  file_extensions = ["sql", "txt", "docx", "pdf", "png", "tar.gz"]
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

resource "google_storage_bucket" "bucket" {
  name                        = local.bucket_name
  location                    = "US"
  force_destroy               = true
  uniform_bucket_level_access = true

  # Disable soft delete so rewritten objects don't leave restorable pre-encryption copies.
  soft_delete_policy {
    retention_duration_seconds = 0
  }
}

resource "random_integer" "fake_objects_size" {
  count = local.num_files
  min   = local.min_size_bytes
  max   = local.max_size_bytes
}

resource "random_id" "fake_objects_content" {
  count       = local.num_files
  byte_length = random_integer.fake_objects_size[count.index].result
}

resource "random_shuffle" "fake_objects_names" {
  count        = local.num_files
  input        = local.wordlist
  result_count = 2
}

resource "random_shuffle" "fake_objects_extensions" {
  count        = local.num_files
  input        = local.file_extensions
  result_count = 1
}

resource "random_shuffle" "fake_objects_name_separators" {
  count        = local.num_files
  input        = [" ", "-", "_"]
  result_count = 1
}

resource "google_storage_bucket_object" "fake_objects" {
  count   = local.num_files
  bucket  = google_storage_bucket.bucket.name
  name    = format("%s.%s", join(random_shuffle.fake_objects_name_separators[count.index].result[0], random_shuffle.fake_objects_names[count.index].result), random_shuffle.fake_objects_extensions[count.index].result[0])
  content = random_id.fake_objects_content[count.index].hex
}

output "display" {
  value = format("GCS bucket %s containing %d fake objects ready", google_storage_bucket.bucket.name, local.num_files)
}

output "bucket_name" {
  value = google_storage_bucket.bucket.name
}
