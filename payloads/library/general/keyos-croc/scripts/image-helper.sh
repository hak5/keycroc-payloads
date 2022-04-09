#!/bin/bash

imagePath=/root/ums
mountPath=/media
payloadPath=/root/binaries

function createImages() {

	label="sneaky"
	size=100

	mkdir -p $imagePath

	# FAT32 (default for != Ubuntu)
	echo "Creating FAT32 image ..."
	dd if=/dev/zero of=$imagePath/fat32.bin bs=1M count=$size
	mkdosfs $imagePath/fat32.bin
	fatlabel $imagePath/fat32.bin "$label"

	# NTFS (needed for direct bin execution on e.g. Ubuntu)
	echo -e "\nCreating NTFS image ..."
	dd if=/dev/zero of=$imagePath/ntfs.bin bs=1M count=$size
	mkfs.ntfs -Q -v -F -L $label $imagePath/ntfs.bin

	echo -e "\nImage creation done !"
}


function clearImage() {
	mkdir -p $mountPath
	echo "Clearing $1 ..."
	mount -o loop $1 $mountPath
	sleep 1
        # remove all files (incl. hidden files) from drive
        rm -r $mountPath/* 2>/dev/null
        rm -r $mountPath/.* 2>/dev/null
	umount $mountPath
}


function prepareImage() {
        mkdir -p $mountPath
        echo "Preparing $1 ..."
        mount -o loop $1 $mountPath
        sleep 1
        # remove all files (incl. hidden files) from drive
        rm -r $mountPath/* 2>/dev/null
        rm -r $mountPath/.* 2>/dev/null
	# copy payloads to the drive
        cp $payloadPath/* $mountPath
        umount $mountPath
}

function clearAllImages() {

	for f in $imagePath/*
	do
		clearImage $f
	done
	echo -e "\nClearing of all available images is done !"
}


function prepareAllImages() {

        for f in $imagePath/*
        do
                prepareImage $f
        done
        echo -e "\nPreparing of all available images is done !"
}

function mountImage() {
	mkdir -p $mountPath
	mount -o loop $1 $mountPath
}


# main
case $1 in

  create)
    createImages
    ;;

  clear)
    if [ ! -z "$2" ]
    then
        clearImage $2
    else
        echo "Image clear failed - path to file missing"
    fi
    ;;

  clearAll)
    clearAllImages
    ;;

  prepare)
    if [ ! -z "$2" ]
    then
        prepareImage $2
    else
        echo "Image prepare failed - path to file missing"
    fi
    ;;

  prepareAll)
    prepareAllImages
    ;;

  mount)
    if [ ! -z "$2" ]
    then
        mountImage $2
    else
        echo "Image mount failed - path to file missing"
    fi
    ;;

esac
