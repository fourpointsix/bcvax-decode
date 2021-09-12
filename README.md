# BC COVID-19 vaccination card decoder
A quick-and-dirty decoder for British Columbia's COVID-19 vaccination card. I built this because I was curious about the format and content of the QR code. It turns out, it's a standard and widely-used format called [SMART Health Card](https://smarthealth.cards/) or SHC for short. I went into detail about its format and authenticity verification in [a comment on Reddit](https://old.reddit.com/r/vancouver/comments/plysaj/bc_vaccine_card_verifier_is_now_live_in_apple_app/hcezuqv/).

# Prerequisites

* Python 3
* (optional) [zxing](https://github.com/dlenski/python-zxing)

# Usage
There are four main ways to decode your vaccine card: QR code, URI argument, URI file, URI standard input. I imagine most will want to use the QR method as it requires the least effort once you have zxing installed.
## QR image (requires zxing)
If you have an image of your QR code and have the [zxing](https://github.com/dlenski/python-zxing) library installed, it can decode the QR code for you.

`$ ./bcvax-decode.py --qr MyVaccineCard.png`

## URI argument
If you've decoded your QR code already or want to experiment with other SHC URIs, you can pass the URI directly on the command line.

`$ ./bcvax-decode.py "shc:/56762959532654603460292540772804..."`

##  URI file
You can pass in one or many SHC URIs to decode by putting them in a file, one on each line, and all will be decoded.

`$ ./bcvax-decode.py MyShcUris.txt`

## URI standard input
You can pass in the same format as the file above, one URI per line, via standard input if that's more your thing. Just specify "-" as the file name and standard input will be used instead.

`$ ./bcvax-decode.py - < MyShcUris.txt`

# Additional Options
By default you'll just see user-friendly formatted card data. You can increase the verbosity of the output with a few flags. These are useful if you want to see all of the raw detail.
```
  --rawdata    Display the base64url data
  --header     Display the header
  --payload    Display the payload
  --signature  Display the signature
  --matchkey   Fetch the card's public key file and check that the key exists. This does not perform any key verification.
```
# Output
By default, output will look something like this:
```
Name: PATIENT, SAMPLE
Birthdate: 2000-01-01

Immunization #1: Pfizer-BioNTech mRNA
  Date: 2021-05-01
  Lot number: FA1234
  Location: A Community Centre - Mass Immunization

Immunization #2: Pfizer-BioNTech mRNA
  Date: 2021-07-01
  Lot number: FA5678
  Location: A Community Centre - Mass Immunization

Vaccination status: Fully vaccinated
```
The vaccination status uses the same technique as the [BC Vaccine Card Verifier](https://github.com/bcgov/BCVAX-Android). Basically, at least two vaccinations are required, or one if it's Johnson & Johnson, to be considered fully vaccinated.
