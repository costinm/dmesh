wget -q -O sdktool.zip "https://dl.google.com/android/repository/sdk-tools-linux-4333796.zip"
echo "Unzipping sdk tools"
unzip sdktool.zip

export PATH=`pwd`/tools/bin:$PATH

echo "Installing sdk components"
echo y | sdkmanager "tools"
echo y | sdkmanager "platform-tools"
echo y | sdkmanager "platforms;android-15"
echo y | sdkmanager "ndk-bundle"

export ANDROID_HOME=`pwd`
export ANDROID_NDK_HOME=$ANDROID_HOME/ndk-bundle

echo "sdk installed in $ANDROID_HOME"
echo "ndk installed in $ANDROID_NDK_HOME"
