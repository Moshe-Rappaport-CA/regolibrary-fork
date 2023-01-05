package armo_builtins


# Fails if workload is Pod
deny[msga] {
    workload := input[_]
	msga := {
		"alertMessage": sprintf("Workload: %v match to menual-review control", [workload.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 3,
		"failedPaths": [],
		"fixPaths": [{"path": "metadata.ownerReferences", "value": "YOUR_VALUE"}],
		"alertObject": {
			"k8sApiObjects": [workload]
		}
	}
}


