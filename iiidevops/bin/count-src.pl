#!/usr/bin/perl
use Carp;

$repo_name = $ENV{'CICD_GIT_REPO_NAME'};
$branch_name = $ENV{'CICD_GIT_BRANCH'};
$commit_id = $ENV{'CICD_GIT_COMMIT'};
$api_origin = $ENV{'api_origin'};
$cloc_report = `cloc .`;
print("\n-----\nrepo_name:[$repo_name]\nbranch_name:[$branch_name]\ncommit_id:[$commit_id]\n-----\n$cloc_report\n");

$cmd_msg = `cloc . | grep SUM:`;
if ($cmd_msg eq '') {
	print("\nERR! [$cmd_msg]\n-----\n");
    exit(1);
}

$cmd_msg =~ s/( )+/,/g;
$cmd_msg =~ s/\n|\r//g;
#SUM,81,1037,1002,59618
($t1,$t2,$t3,$t4,$source_code_num) = split(",", $cmd_msg);
if ($t1 ne 'SUM:') {
	print("\nERR! [$cmd_msg]\n-----\n");
	exit(1);
}

$json_data = <<END;
{"repo_name": "$repo_name",
"branch_name": "$branch_name",
"commit_id": "$commit_id",
"source_code_num": $source_code_num}
END

$cmd = "curl --location -s --request POST '$api_origin/repositories/pipline' --header 'Content-Type: application/json' --data-raw '$json_data'";
$cmd_msg = `$cmd`;
print("\n-----\n$cmd\n-----\n$cmd_msg-----\n");
