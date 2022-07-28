#!/usr/bin/perl
use Carp;

$project = $ENV{'CICD_GIT_REPO_NAME'};
$branch = $ENV{'CICD_GIT_BRANCH'};

$cmd_msg = `cloc . --json`;
print("\n-----\n$cmd_msg\n-----\n");
