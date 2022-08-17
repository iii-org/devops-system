#! /bin/bash

cd ./devops-data/project-data/$1/pipeline/$2/
cat sbom_* >sbom.tar

