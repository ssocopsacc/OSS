PACKAGE=xerces-c-2.8.0
PACKAGE_SRC=$PACKAGE.tar.gz
PKG_DIR=$PACKAGE
BASE_DIR=`pwd`
DEVEL_DIR=$BASE_DIR/devel
BITS_FILE=$BASE_DIR/bits
BITS=$2
SO_OBJECT=$DEVEL_DIR/lib/libxerces-c.so.28.0

clean()
{
	echo cleaning Xerces..
	rm -rf build/$PKG_DIR
	rm -rf $DEVEL_DIR/include
	rm -rf $DEVEL_DIR/lib
	rm -f $BITS_FILE
}

build()
{
PREV_BITS=$(cat $BITS_FILE)
#	if [ -e $SO_OBJECT -a "$PREV_BITS" == "$BITS" ]; then
#		echo "Xerces for '$BITS' Bits already exist. Not rebuilding.."
#	else
		clean
		cd build
		tar -zxvf $BASE_DIR/$PACKAGE_SRC
		export XERCESCROOT=`pwd`/$PKG_DIR
		cd $PKG_DIR/src/xercesc
		./runConfigure -p linux -b $BITS -P $DEVEL_DIR
		make all install
		strip $DEVEL_DIR/lib/*
		if [ -e $SO_OBJECT ]; then
			echo $BITS > $BITS_FILE
		fi
#	fi
}

usage()
{
	echo "Usage: $0 <clean | build <32|64>>"
	exit 1
}


if [ "$1" == "clean" ]; then
	clean
elif [ "$1" == "build" ]; then
	if [ "$BITS" != "32" -a "$BITS" != "64" ]; then
		usage
	else
		build
	fi
else
	usage
fi

