#!/bin/bash
if [ $# -lt 5 ]; then
    echo "usage: $0 keychain_file cert_identity profile_provisioning inpath_app outpath_ipa" >&2
    exit 1
fi
KEYCHAIN="$1"
IDENTITY="$2"
PROFILE="$3"
APP_DIR="$4"
APP_DEST=temp/Payload/$(basename $APP_DIR)
DEST_IPA="$5"

echo "create ipa structure with app at $APP_DEST"
mkdir -p $APP_DEST
cp -Rf $APP_DIR/* $APP_DEST
echo "copy chosen mobileprovision into new app structure"
cp $PROFILE $APP_DEST/embedded.mobileprovision
echo "sign application with chosen identity $IDENTITY"
codesign -f -s "$IDENTITY" --keychain "$KEYCHAIN" --resource-rules="$APP_DEST/ResourceRules.plist" $APP_DEST || exit 1
echo "zip tmp app to ipa file"
cd temp; zip -qr $DEST_IPA ./*;cd ..
echo "remove tmp dir"
rm -rf "temp"
exit 0
