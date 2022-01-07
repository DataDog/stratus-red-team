package main

//TODO: user inputs + pre-requisites + terraform
//(think about K8s for instance )

import (
	"fmt"

	cr "./attacktechniques/aws/persistence"
)

func init() {
	fmt.Println("Hello from init")
}

func Main() {
	fmt.Println("hello from main")
	cr.Foo()
}
