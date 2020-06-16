package main
//
//import (
//	"encoding/json"
//	"github.com/google/syzkaller/pkg/ipc"
//	"github.com/google/syzkaller/pkg/log"
//	"io/ioutil"
//)
//
//const pathToInput = "/exec/input.json"
//const pathToEnv = "/exec/env.json"
//
////entrypoint for container
////check for a serialized env and input in some file that should be mounted as a volume
////then call Exec
//func main() {
//
//	//if len(os.Args)	< 2 {
//	//	log.Fatalf("detected no arg for executor. Path to executor must be first command line arg")
//	//}
//	//executor := os.Args[1]
//
//	inputFile, err := ioutil.ReadFile(pathToInput)
//	if err != nil {
//		log.Fatalf("could not read inputfile: %v", err)
//	}
//	envFile, err := ioutil.ReadFile(pathToEnv)
//	if err != nil {
//		log.Fatalf("could not read envfile: %v", err)
//	}
//	env := ipc.Env{}
//	if err = json.Unmarshal(envFile, &env); err != nil {
//		log.Fatalf("could not unmarshal env: %v\n env json: %v", err, envFile)
//	}
//	input := ipc.ExecInput{}
//	if err = json.Unmarshal(inputFile, &input); err != nil {
//		log.Fatalf("could not unmarshal input: %v\ninput json: %v", err, inputFile)
//	}
//	output, info, hanged, err := env.Exec(input.Opts, input.P)
//	result := ipc.ExecOutput{Output: output, Info: info, Hanged: hanged, Err0:err}
//	resultJson, err := json.Marshal(result)
//	if err != nil {
//		log.Fatalf("could not marshal output: %v", err)
//	}
//	print(resultJson)
//}
