terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "4.57.0"
    }
  }
}

provider "azurerm" {
  features {}
}

resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

locals {
  resource_prefix      = "stratusrt"
  storage_account_name = "${local.resource_prefix}${random_string.suffix.result}"
  num_files            = 51
  num_containers       = 5
  min_size_bytes       = 1
  max_size_bytes       = 200
  file_extensions      = ["sql", "txt", "docx", "pdf", "png", "tar.gz"]
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

resource "azurerm_resource_group" "rg" {
  name     = "stratus-red-team-storage-deletion-rg-${random_string.suffix.result}"
  location = "West US"
}

resource "azurerm_storage_account" "storage" {
  name                     = local.storage_account_name
  resource_group_name      = azurerm_resource_group.rg.name
  location                 = azurerm_resource_group.rg.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  blob_properties {
    versioning_enabled = true
  }
}

resource "azurerm_storage_container" "containers" {
  count                 = local.num_containers
  name                  = "container-${count.index + 1}"
  storage_account_name  = azurerm_storage_account.storage.name
  container_access_type = "private"
}

resource "random_integer" "fake_blobs_size" {
  count = local.num_files
  min   = local.min_size_bytes
  max   = local.max_size_bytes
}

resource "random_id" "fake_blobs_content" {
  count       = local.num_files
  byte_length = random_integer.fake_blobs_size[count.index].result
}

resource "random_shuffle" "fake_blobs_names" {
  count        = local.num_files
  input        = local.wordlist
  result_count = 2
}

resource "random_shuffle" "fake_blobs_extensions" {
  count        = local.num_files
  input        = local.file_extensions
  result_count = 1
}

resource "random_shuffle" "fake_blobs_name_separators" {
  count        = local.num_files
  input        = [" ", "-", "_"]
  result_count = 1
}

resource "azurerm_storage_blob" "fake_blobs" {
  count                  = local.num_files
  name                   = format("%s.%s", join(random_shuffle.fake_blobs_name_separators[count.index].result[0], random_shuffle.fake_blobs_names[count.index].result), random_shuffle.fake_blobs_extensions[count.index].result[0])
  storage_account_name   = azurerm_storage_account.storage.name
  storage_container_name = azurerm_storage_container.containers[count.index % local.num_containers].name
  type                   = "Block"
  source_content         = random_id.fake_blobs_content[count.index].hex
}

output "display" {
  value = format("Storage account %s containing %d blobs across %d containers ready", azurerm_storage_account.storage.name, local.num_files, local.num_containers)
}

output "storage_account_name" {
  value = azurerm_storage_account.storage.name
}

output "resource_group_name" {
  value = azurerm_resource_group.rg.name
}

output "container_names" {
  value = [for container in azurerm_storage_container.containers : container.name]
}
