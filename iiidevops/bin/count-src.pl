#!/usr/bin/perl
use Carp;

$branch = $ENV{'CICD_GIT_BRANCH'};

$cmd_msg = `git ls-files | xargs cat | wc -l`;
print("\n-----\n$cmd_msg\n-----\n");
