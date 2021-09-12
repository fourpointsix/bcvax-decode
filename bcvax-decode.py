#!/usr/bin/python3

import argparse
import fileinput
import base64
import zlib
import json
import urllib.request

try:
    import zxing
    readsQr = True
except ModuleNotFoundError:
    readsQr = False

# All of the COVID-19 SNOMED vaccine codes found in this Excel sheet:
# https://www2.gov.bc.ca/assets/gov/health/practitioner-pro/health-information-standards/bc-snomed-mapping-din-pin-vaccinations.xlsx
snomedDisplayNames = {
    '28761000087108': 'AstraZenica',
    '28571000087109': 'Moderna mRNA',
    '28961000087105': 'Covishield',
    '28951000087107': 'Johnson & Johnson',
    '29171000087106': 'Novavax',
    '28581000087106': 'Pfizer-BioNTech mRNA'
}

# These vaccines only need a single dose to be considered fully vaccinated in BC
oneDoseVaccines = [
    '28951000087107'    # Johnson & Johnson
]

# Map the CVX code to SNOMED if the SNOMED code isn't in the data.
# I had to Google for these and found them on a US CDC page:
# https://www.cdc.gov/vaccines/programs/iis/COVID-19-related-codes.html
cvxToSnomed = {
    '210': '28761000087108',    # AstraZenica
    '207': '28571000087109',    # Moderna
    # Duplicate code for Covishield because both are AZ. '210': '28961000087105'   # Covishield
    '212': '28951000087107',    # Johnson & Johnson
    '211': '29171000087106',    # Novavax
    '208': '28581000087106'     # Pfizer
}

# Convert a string of digits into a string of decoded text by converting each digit pair into its
# base-10 numeric value, adding 45, and then converting it into the ASCII character at that code
# point.
# eg. '56' -> 56 + 45 = 101 -> chr(101) -> 'e'
def numericDecode(s):
    decoded = ''
    for charCode in ((int(s[index:index + 2]) + 45) for index in range(0, len(s), 2)):
        decoded += chr(charCode)

    return decoded

# Decode a base64url string, padding it as necessary to be a multiple of 4 in length.
def base64UrlDecode(s):
    return base64.b64decode(s + ('=' * (len(s) % 4)), altchars=b'-_')

# Inflate a raw DEFLATE payload. Since it's raw, we need to specify a negative window size to let
# zlib know not to look for a header.
def inflate(deflated):
    return zlib.decompress(deflated, -zlib.MAX_WBITS)

# Print some text between two thick horizontal lines
def printCardHeader(s):
    horizLine = ('=' * (len(s) + 2))
    print('\n' + horizLine + '\n ' + s + '\n' + horizLine)

# Print some text with a whimsical, squiggly underline
def printSectionHeader(s):
    print('\n' + s + '\n' + ('~' * len(s)))

# Read the public key URL from the payload, fetches its content, and looks for a matching key.
# If found, it returns the key. Note that no validation takes place beyond matching the key ID
# and ignoring keys with incompatible properties.
def getPublicKey(headerJson, payloadJson):
    keyId = headerJson.get('kid')
    if not keyId:
        print('No key ID found in header')
        return

    # Health Cards Framework only supports ES256 so we might as well sanity check for that
    algorithm = headerJson.get('alg')
    if algorithm != 'ES256':
        print(f'Unsupported algorithm {algorithm}')
        return

    issUrl = payloadJson.get('iss')
    if not issUrl:
        print('Missing issuer URL in payload')
        return

    jwksUrl = issUrl + '/.well-known/jwks.json'
    print(f'Fetching public keys from {jwksUrl}')
    response = urllib.request.urlopen(jwksUrl)
    jkwsJson = json.loads(response.read().decode())

    jkwsKeys = jkwsJson.get('keys')
    if not jkwsKeys:
        print('No keys found')
        return

    for jkwsKey in jkwsKeys:
        # Only look at signing keys
        if jkwsKey.get('use') != 'sig':
            continue

        # Health Cards Framework only supports elliptic-curve key types
        if jkwsKey.get('kty') != 'EC':
            continue

        # Health Cards Framework only supports the P-256 curve
        if jkwsKey.get('crv') != 'P-256':
            continue

        # Health Cards Framework only supports the ES256 algorithm
        if jkwsKey.get('alg') != 'ES256':
            continue

        # Health Cards Framework requires the "d" parameter not be present
        if jkwsKey.get('d'):
            continue

        jkwsKeyId = jkwsKey.get('kid')
        if jkwsKeyId == keyId:
            print(f'Found matching key {keyId}')
            return jkwsKey

def printPatient(payloadJson):
    try:
        # Filter the resource entities into patients and vaccines. Assume there'll only be one
        # patient even though the format allows for multiple patients because this is what the
        # BC Vaccine Card Verifier does.
        entries = payloadJson['vc']['credentialSubject']['fhirBundle']['entry']
        immunizations = []
        patient = None
        for entry in entries:
            if entry['resource']['resourceType'] == 'Patient':
                patient = entry['resource']
            if entry['resource']['resourceType'] == 'Immunization':
                immunizations.append(entry['resource'])

        if not patient:
            print('No patient found')
            return

        # Most people wil only have one name, but it's possible to have many.
        for name in patient['name']:
            familyName = name['family']
            givenNames = ' '.join(name['given'])
            print(f'Name: {familyName}, {givenNames}')

        print(f'Birthdate: {patient["birthDate"]}')

        immunizationNum = 0
        oneDoseImmunizations = 0
        twoDoseImmunizations = 0

        for immunization in immunizations:
            immunizationNum += 1

            snomedCode = None

            # Determine which vaccine it was. There are multiple coding systems so loop over
            # all of them and normalize to a single SNOMED code.
            for coding in immunization['vaccineCode']['coding']:
                if coding['system'] == 'http://hl7.org/fhir/sid/cvx':
                    snomedCode = cvxToSnomed[coding['code']]
                elif coding['system'] == 'http://snomed.info/sct':
                    snomedCode = coding['code']

            # Convert the vaccine's SNOMED code into a user-friendly name for display
            if snomedCode:
                vaccineName = snomedDisplayNames[snomedCode]
                if snomedCode in oneDoseVaccines:
                    oneDoseImmunizations += 1
                else:
                    twoDoseImmunizations += 1
            else:
                vaccineName = '(unknown)'

            print('')
            print(f'Immunization #{immunizationNum}: {vaccineName}')
            print('  Date: ' + immunization.get('occurrenceDateTime', '(unspecified)'))
            print('  Lot number: ' + immunization.get('lotNumber', '(unspecified)'))
            for performer in immunization.get('performer', []):
                print(f'  Location: {performer["actor"]["display"]}')

        # Use the same technique as the BC Vaccine Card Verifier to determine vaccination status
        vaccinationStatus = 'Unvaccinated'
        if (oneDoseImmunizations > 0) or (twoDoseImmunizations > 1):
            vaccinationStatus = 'Fully vaccinated'
        elif (twoDoseImmunizations == 1):
            vaccinationStatus = 'Partially vaccinated'

        print(f'\nVaccination status: {vaccinationStatus}')

    except (KeyError, json.decoder.JSONDecodeError) as ex:
        print('Malformed payload: ' + repr(ex))
        return

def decodeShcUri(shcUri, args):
    # Remove "shc:/" protocol specifier
    shcUri = shcUri.replace('shc:/', '')

    # Check for chunk instructions
    if (shcUri.find('/') != -1):
        print('Chunked JWS not supported')
        return

    # Decode to base64
    jwsData = numericDecode(shcUri)
    if args.rawdata:
        printSectionHeader('Base64url data')
        print(jwsData)

    # Split into header, payload, signature
    jwsParts = jwsData.split('.')

    if len(jwsParts) == 0:
        print('Invalid JWS')
        return

    if len(jwsParts) == 5:
        print('This appears to be a JSON Web Encryption payload. JWS was expected.')
        # Continue to display the next error before exiting

    if len(jwsParts) > 3:
        print(f'\nMore JWS parts ({len(jwsParts)}) than expected (3) were found')
        return

    # Decode the header
    jwsHeader = base64UrlDecode(jwsParts[0]).decode()
    if args.header:
        printSectionHeader('Header')
        print(jwsHeader)

    # Decode the payload
    jwsPayload = inflate(base64UrlDecode(jwsParts[1])).decode()
    if args.payload:
        printSectionHeader(f'Payload')
        print(jwsPayload)

    # Decode the signature
    jwsSignatureBase64 = jwsParts[2]
    if args.signature:
        printSectionHeader('Signature (Base64url)')
        print(jwsSignatureBase64)

    # Parse the sections into their JSON objects
    headerJson = json.loads(jwsHeader)
    payloadJson = json.loads(jwsPayload)

    if args.matchkey:
        pubKey = getPublicKey(headerJson, payloadJson)

    print('')
    printPatient(payloadJson)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('uri', default='-', help='The shc:/ URI that the QR code represents, or a file name, or "-" to read from stdin')
    parser.add_argument('--rawdata', action='store_true', help='Display the base64url data')
    parser.add_argument('--header', action='store_true', help='Display the header')
    parser.add_argument('--payload', action='store_true', help='Display the payload')
    parser.add_argument('--signature', action='store_true', help='Display the signature')
    parser.add_argument('--matchkey', action='store_true', help='Fetch the card\'s public key file and check that the key exists. This does not perform any key verification.')

    if readsQr:
        parser.add_argument('--qr', action='store_true', help='Interpret the input as a QR code image rather than an SHC URI')

    args = parser.parse_args()

    if args.uri.startswith('shc:/'):
        decodeShcUri(args.uri, args)
    elif readsQr and args.qr:
        printCardHeader(f'SMART Health Card QR')
        reader = zxing.BarCodeReader()
        qrCode = reader.decode(args.uri, try_harder=True, possible_formats=['QR_CODE'])

        if qrCode:
            decodeShcUri(qrCode.raw, args)
        else:
            print('No QR code found in image')
    else:
        shcCount = 0
        for line in fileinput.input(files=args.uri):
            shcCount += 1
            if readsQr and args.qr:
                print('Reading QR')
                reader = zxing.BarCodeReader()
                shcUri = reader.decode(args.qrimage)
                print(shcUri)
            else:
                shcUri = line.strip()

            printCardHeader(f'SMART Health Card #{shcCount}')
            decodeShcUri(shcUri, args)

if __name__ == "__main__":
    main()