distios
=======

DistIOS is a very simple tool to distribute your Ad-HOC IOS application very
easyly. 
Dependencies : `MacOSX + XCode + Xcode command line tools + python3.3`

- Configure the applications you want to distribute, 
- set up a google drive account to host the application distribution website,
  different IPAs and there plist.
- set up a google spreadsheet with an associated google form to add, list, and
  moderate devices you want to add to your ad-hoc distribution.
- set up a google API application with its client id and client secret.
- set up the IOS application repository, branch, build configuration and build
  target to allow the script to compile the application
- customize the distribution website : customize the html template and css

Then run the script `update_google_drive`, authorize with OAuth the application
with an account with read/write permissions on the given spreadsheet and
folder. Then the script will handle the entire distribution process through a nice web UI :

- Clone the repo and check if the given branch is synchronised in `/build/nomrepo-repo`.
- Compile the application if not present in `/build/nomtarget.app`.
- Create a PNG icon for the App from the generated application icon, put it in `/nomtarget.png`.
- Ask you to upload a provisioning profile 
- check that the profile application identifier match the application bundler
  identifier, ask you a new profile if not.
- Check that all moderated devices UDID from the spreadsheet are present in the
  provisioning profile, ask you a new profile if not, and provide the missing
  UDIDs in a file that can be directly imported in the IOS portal.
- Check that you have in `/distribute.keychain` the certificate given in the profile.
- Check that the certificate is not outdated and still valid.
- Check that the certificate identity is valid because you have a matching
  private key in `/distribute.keychain`
- Sign the application with the valid certificate and embed the valid profile
  then create the IPA archive containing it in `/nomtarget.ipa`
- Create the associated plist distribute file, with a link to ipa file in
  `/nomtarget-distribute.plist`
- Create the HTML page `/index.html` containing valid applications, ready to
  distribute, with link to plist to allow wireless IOS application installation.
- Check that the goole drive containing the website is sync to local website
  and upload different files if necessary.

You know can give the google link to the website host on google drive to the
ipad owners, they can add it to their main screen and then download and update
the Ad-Hoc applications in one click.

You can give the google form link associated to the device spreadsheet to the company
employees to allow them to ask for adding their devices with a simple form.

A moderator can check the device spreadsheet to moderate the device that you
really want to add to your distribution.

The script does all the steps to validate and distribute the applications.

## More details about the script configuration are coming
