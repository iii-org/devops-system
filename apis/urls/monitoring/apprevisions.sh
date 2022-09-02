#! /bin/bash
export NS=$(kubectl get project -n local -o jsonpath="{.items[?(@.spec.displayName=='Default')].metadata.name}")
export Kind=apprevisions

kubectl get $Kind -n $NS|grep -v NAME|awk '{print $1}'
kubectl delete $Kind $(kubectl get $Kind -n $NS|grep -v NAME|awk '{print $1}') -n $NS