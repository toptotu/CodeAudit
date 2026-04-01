// This file is intentionally vulnerable for testing CodeAudit.
// DO NOT use in production.
package samples

import (
	"crypto/md5"  //nolint
	"crypto/tls"  //nolint
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"
)

var db *sql.DB

// InsecureQuery is vulnerable to SQL injection.
func InsecureQuery(userInput string) {
	query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", userInput)
	db.Query(query) //nolint:errcheck
}

// InsecureMD5 uses a broken hash function.
func InsecureMD5(data []byte) []byte {
	h := md5.New()
	h.Write(data)
	return h.Sum(nil)
}

// InsecureExec is vulnerable to command injection.
func InsecureExec(filename string) {
	exec.Command("cat", filename).Run() //nolint:errcheck
}

// InsecureTLS disables certificate verification.
func InsecureTLS() *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec
		},
	}
	return &http.Client{Transport: tr}
}

// HardcodedSecret contains a hardcoded credential.
const password = "supersecretpassword123" //nolint:gosec
