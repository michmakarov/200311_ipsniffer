#!/bin/bash

#This is a script for building the project so that the executable know the last git commit and the date of building

git_commit=no_git???
#build_date=no_date
compiltime=No_compilation_time
date +%y%m%d_%H%M > compilation_time.txt
git log --pretty=format:"%h" -n 1 > git_commit.txt

git_commit=$(cat git_commit.txt)
compiltime=$(cat compilation_time.txt)

git_commit_1=(commit--$git_commit--date--$compiltime)
echo ================================
echo $git_commit_1
echo ================================




go build -ldflags "-X main.git_commit_1=$git_commit_1"

rm git_commit.txt
rm compilation_time.txt

# rm *.log


