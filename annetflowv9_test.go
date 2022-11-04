package ANNetflowv9

import (
	"io/ioutil"
	"os"
	"testing"
)

func TestNewNetFlowV9Collector(t *testing.T) {
	TestWrongData := []byte{0x00, 0x09, 0x03, 0xff, 0x00, 0x00, 0x04, 0x70, 0x00}
	Ncol := NewNetFlowV9Collector()
	if !Ncol.initialized {
		t.Errorf("Error when initialised")
	}

	var Ncol2 NetFlowV9Collector
	_, Err := Ncol2.ParceNetflov9data(&TestWrongData, "192.168.0.7", 255)
	if Err == nil {
		t.Errorf("Expected error")
	}

	_, Err = Ncol.ParceNetflov9data(&TestWrongData, "192.168.0.7", 255)
	if Err == nil {
		t.Errorf("Expected error")
	} else {
		if Err.Error() != "runtime error: slice bounds out of range [:12] with capacity 9" {
			t.Errorf("%s", Err)
		}
	}

	f, err2 := os.Open("netflowtempletes.bin")
	if err2 != nil {
		t.Errorf("%s", err2)
	}
	defer f.Close()
	TempleteData, _ := ioutil.ReadAll(f)

	f2, err3 := os.Open("netflowdata.bin")
	if err3 != nil {
		t.Errorf("%s", err3)
	}
	defer f2.Close()
	NetflowData, _ := ioutil.ReadAll(f2)

	JsData, Nerr := Ncol.ParceNetflov9data(&TempleteData, "192.168.0.7", 0)
	if Nerr != nil {
		t.Errorf("Error: %s", Nerr)
	}

	if len(Ncol.Hosts["192.168.0.7"].NetFlowTempletes) == 0 {
		t.Errorf("Error: %s", "No templete found")
	}

	if len(Ncol.Hosts["192.168.0.7"].NetFlowTempletes) != 16 {
		t.Errorf("Found %d templetes, expected 17 templetes", len(Ncol.Hosts["192.168.0.7"].NetFlowTempletes))
	}

	if len(JsData) > 0 {
		t.Errorf("Found number of data %d , expected only templetes", len(JsData))
	}

	//Повторно заполняем данные шаблонов
	JsData, Nerr = Ncol.ParceNetflov9data(&TempleteData, "192.168.0.7", 0)
	if Nerr != nil {
		t.Errorf("Error: %s", Nerr)
	}

	JsData, Nerr = Ncol.ParceNetflov9data(&NetflowData, "192.168.0.7", 0)
	if Nerr != nil {
		t.Errorf("Error: %s", Nerr)
	} else {
		if len(JsData) != 19 {
			t.Errorf("Found number of data %d , expected 19", len(JsData))
		}
		if len(JsData) > 0 {
			if JsData[0].SRC_ip != "192.168.55.94" {
				t.Errorf("IP source in JsData[0] is %s , expected 10.10.2.36", JsData[0].SRC_ip)
			}
		}
	}

	JsData, Nerr = Ncol.ParceNetflov9data(&NetflowData, "192.168.0.8", 0)
	if Nerr != nil {
		t.Errorf("Error: %s", Nerr)
	} else {
		if len(JsData) > 0 {
			t.Errorf("Len of JsData is %d , expected 0", len(JsData))
		}
	}
}
