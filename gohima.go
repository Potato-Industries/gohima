package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strconv"
	"time"
	"github.com/ghodss/yaml"
	"github.com/tidwall/gjson"
	"www.velocidex.com/golang/evtx"
	"github.com/ryanuber/go-glob"
)

var (
	ruleset = make(map[string]map[string]interface{})
)

func doMitigateKillPID(pid float64) {
	processId := strconv.Itoa(int(pid))
	kill := exec.Command("taskkill", "/T", "/F", "/PID", processId)
	err := kill.Run()
	if err != nil {}
}

func doInList(a interface{}, list interface{}) bool {
	
	switch a.(type) {
	case float64:
		tmp := list.([]interface{})
		for _, b := range tmp {
			if b == a {
				return true
			}
		}
	case string:
		tmp := list.([]interface{})
		for _, b := range tmp {
			if glob.Glob(b.(string), a.(string)) {
				return true
			}
		}
	}
	return false
}


func doMatch(data string) {
	
	result, ok := gjson.Parse(data).Value().(map[string]interface{})
	if !ok {}

	Event, ok := result["Event"].(map[string]interface{})
	if !ok {}

	EventData, ok := Event["EventData"].(map[string]interface{})
	if !ok {}

	System, ok := Event["System"].(map[string]interface{})
	if !ok {}

	EventID, ok := System["EventID"].(map[string]interface{})
	if !ok {}

	for key, sig := range ruleset {
		detection, ok := sig["detection"].(map[string]interface{})
		if !ok {
			continue
		}
		selection, ok := detection["selection"].(map[string]interface{})
		if !ok {
			continue
		}

		//support filters

		//support keywords

		total := len(selection)
		matched := 0
		checkfailed := 0
		fmt.Println("RuleSet Name: ", key)
		fmt.Println("Signatures Total: ", total)

		for signature_key, signature_value := range selection {
			if checkfailed == 1 {
				break
			}
			fmt.Println("--------------------------RULE--------------------------")
			fmt.Println("signature_key: ", signature_key)
			fmt.Println("signature_value: ", signature_value)

			if signature_key == "EventID" && EventID["Value"] != nil {

				switch signature_value.(type) {
				case nil:
					break
				case []interface {}:
					if doInList(EventID["Value"].(float64), signature_value) == false {
						checkfailed = 1
						break
					}
					matched = matched + 1
					break

				case float64:
					if EventID["Value"] != signature_value {
						checkfailed = 1
						break
					}
					matched = matched + 1
				}

			}
			if signature_key != "EventID" && EventData[signature_key] != nil {
				switch signature_value.(type) {
				case nil:
					break
				case []interface{}:
					if doInList(EventData[signature_key], signature_value) == false {
						checkfailed = 1
						break
					}
					matched = matched + 1

				case float64:
					if EventData[signature_key] != signature_value {
						checkfailed = 1
						break
					}
					matched = matched + 1

				case string:
					if EventData[signature_key] == nil {
						checkfailed = 1
						break
					}

					if !glob.Glob(signature_value.(string), EventData[signature_key].(string)) {
						checkfailed = 1
						break
					}
					matched = matched + 1
				}

			}

		}

		fmt.Println("--------------------------END---------------------------")
		fmt.Println("Rules Matched: ", matched, "Total: ", total, "Alert: ", matched == total)
		fmt.Println("--------------------------END---------------------------")
		if matched == total {
			fmt.Println("--------------------------ACT---------------------------")
			fmt.Println("Calling Kill PID:", EventData["ProcessId"])
			fmt.Println("--------------------------ACT---------------------------")
			doMitigateKillPID(EventData["ProcessId"].(float64))
		}

	}

}

func doLoadRuleSet() {
	fmt.Println("Loading rules..")
	searchDir := "rules\\"
	files, err := ioutil.ReadDir(searchDir)
	if err != nil {
		fmt.Println("ERROR: Loading rules.", err)
	}
	for _, f := range files {
		fmt.Println(f.Name())
		file, err := os.Open(searchDir + f.Name())
		if err != nil {
			continue
		}
		defer file.Close()
		b, err := ioutil.ReadAll(file)
		if err != nil {
			continue
		}
		fmt.Println(string(b))
		jsonOutput, err := yaml.YAMLToJSON(b)
		if err != nil {
			continue
		}

		signature, ok := gjson.Parse(string(jsonOutput)).Value().(map[string]interface{})
		if !ok {
			continue
		}

		ruleset[f.Name()] = signature

		fmt.Println("Rules loaded..")

	}

}

func doWatch() {
	fd, err := os.OpenFile("c:\\Windows\\System32\\Winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx", os.O_RDONLY, os.FileMode(0666))
	if err != nil {
		os.Exit(0)
	}

	open_file := func(fd *os.File) []*evtx.Chunk {
		chunks, err := evtx.GetChunks(fd)
		if err != nil {
			os.Exit(0)
		}
		return chunks
	}

	doLoadRuleSet()

	max_record_id := uint64(1)
	new_max_record_id := max_record_id

	chunks := open_file(fd)
	for _, chunk := range chunks {
		end_of_chunk := chunk.Header.LastEventRecID
		if max_record_id > 0 && end_of_chunk > max_record_id {
			records, err := chunk.Parse(int(max_record_id))
			if err != nil {
				continue
			}

			for _, i := range records {
				if i.Header.RecordID > new_max_record_id {
					new_max_record_id = i.Header.RecordID
				}
			}
		}
	}

	max_record_id = new_max_record_id - 1

	fmt.Printf("Watching Sysmon events newer than ID: %v\n", max_record_id)

	for {

		chunks := open_file(fd)
		for _, chunk := range chunks {
			end_of_chunk := chunk.Header.LastEventRecID
			if max_record_id > 0 && end_of_chunk > max_record_id {
				records, err := chunk.Parse(int(max_record_id))
				if err != nil {
					continue
				}

				for _, i := range records {
					data, _ := json.MarshalIndent(i.Event, " ", " ")
					println(string(data))
					data, _ = json.Marshal(i.Event)


					doMatch(string(data))

					if i.Header.RecordID > new_max_record_id {
						new_max_record_id = i.Header.RecordID
					}
				}
			}
		}

		max_record_id = new_max_record_id
		time.Sleep(500 * time.Millisecond)
	}
}

var options struct {
	agree bool
}

func main() {

	var Usage = func() {
		fmt.Println("gohima.exe (https://github.com/PotatoIndustries/gohima)\n")
		fmt.Println("a proof of concept Go based local intrusion mitigation agent for Windows platform.\n")
		fmt.Fprintf(os.Stderr, "Usage: %s\n", os.Args[0])
		flag.PrintDefaults()

		fmt.Println("\nNOTE: This is an experimental tool, not for production use.\n\ngohima.exe monitors your live local sysmon eventlogs, performs signature matching based on configured Sigma .yml rulesets to detect intrusion and automatically kills processes upon detection. Use with caution!")
	}

	flag.BoolVar(&options.agree, "agree", false, "Set this flag to run gohima.exe.")
	flag.Parse()

	var intPtr *bool
	intPtr = &options.agree

	if intPtr != nil {
		if *intPtr != true {
			Usage()
			os.Exit(0)
		}
		doWatch()

	}
	os.Exit(0)

}
