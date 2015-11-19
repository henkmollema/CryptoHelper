#!/usr/bin/env bash

if test `uname` = Darwin; then
    cachedir=~/Library/Caches/KBuild
else
    if [ -z $XDG_DATA_HOME ]; then
        cachedir=$HOME/.local/share
    else
        cachedir=$XDG_DATA_HOME;
    fi
fi

mkdir -p $cachedir
cachePath=$cachedir/nuget.latest.exe
url=https://dist.nuget.org/win-x86-commandline/latest/nuget.exe
if test ! -f $cachePath; then
    wget -O $cachePath $url 2>/dev/null || curl -o $cachePath --location $url /dev/null
fi

if test ! -e .nuget; then
    mkdir .nuget
    cp $cachePath .nuget/nuget.exe
fi

if test ! -d packages/KoreBuild; then
    mono .nuget/nuget.exe install KoreBuild -version 0.2.1-beta7 -Source https://www.myget.org/F/aspnetmaster/api/v2 -o packages -nocache -pre -ExcludeVersion
    mono .nuget/nuget.exe install Sake -version 0.2.0 -Source https://www.nuget.org/api/v2/ -o packages -ExcludeVersion
fi

if ! type dnvm > /dev/null 2>&1; then
    source packages/KoreBuild/build/dnvm.sh
fi

DNX_FEED=https://www.nuget.org/api/v2/
if ! type dnx > /dev/null 2>&1; then
    dnvm upgrade -r mono
fi

mono packages/Sake/tools/Sake.exe -I packages/KoreBuild/build -f makefile.shade "$@"
