// Functions

// Create and style the button
function createDefaultButton(){
    const button = document.createElement('button');

    button.id = "run-asterio";
    button.textContent = 'Run Asterio!';
    button.style.position = 'fixed';
    button.style.bottom = '10px';
    button.style.right = '10px';
    button.style.zIndex = '1000';
    button.style.padding = '10px';
    button.style.backgroundColor = '#007bff';
    button.style.color = '#fff';
    button.style.border = 'none';
    button.style.borderRadius = '5px';
    button.style.cursor = 'pointer';

    return button;
}

// Fetch Requests
function scanUrlWithVirusTotal(identifier, type) {
    // IPs -> https://www.virustotal.com/api/v3/ip_addresses/{ip}
    // Domains -> https://www.virustotal.com/api/v3/domains/{domain}
    // URLs -> https://www.virustotal.com/api/v3/urls/{id}

    var endpoints = {
        "ip":`https://www.virustotal.com/api/v3/ip_addresses/${identifier}`,
        "domain":`https://www.virustotal.com/api/v3/domains/${identifier}`,
        "url":`https://www.virustotal.com/api/v3/urls/${identifier}`
    }

    var url = endpoints[type];
    chrome.runtime.sendMessage({ action: "fetchData", url: url }, (response) => {
        if (response.data) {
        //   console.log(`Scan results for ${url}:`, response.data);
        //   alert(`Scan results for ${url}: ${JSON.stringify(response.data, null, 2)}`);
        // get the element that holds the results
        const artifactsResults = document.getElementById("artifacts");
        console.log(artifactsResults);
        const newResult = `<div class="artifact-result">
                                <div>Artifact</div>
                                <div>Result</div>
                            </div>`
        artifactsResults.innerHTML += newResult;
        } else {
          console.error('Error:', response.error);
        }
      });
}

const button = createDefaultButton();
document.body.appendChild(button);

// We will collect the following artifacts
/* 
    1. Emails
    2. Domains
    3. IPs
    4. URLs
*/

// Steps
/* 
    1. Parse the HTML
    2. Get the text content only
    3. Check each string in the text collected
*/

// URLs & Domains & IPs
/* 
    1. <a href="url"></a> tag
    2. plain text
    3. JS Code ( later )
*/

// Emails
/* 
    1. sendTo
    2. plain text
    3. JS Code ( later )
*/

// To extract the data we will check
function extractArtifacts() {
    const htmlContent = document.documentElement.outerHTML;
    const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
    const ipRegex4 = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
    const dnsRegex = /\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,6}\b/g;
    const sUrlRegex = /https?:\/\/[^\s/$.?#].[^\s]*/g;
    const urlRegex = /http?:\/\/[^\s/$.?#].[^\s]*/g;

    // Extract artifacts using the regular expressions
    const emails = htmlContent.match(emailRegex) || [];
    const ips = htmlContent.match(ipRegex4) || [];
    const dnsNames = htmlContent.match(dnsRegex) || [];
    const urls = htmlContent.match(urlRegex) || [];
    
    // Log the extracted artifacts to the console
    console.log('Emails:', emails);
    console.log('IPs:', ips);
    console.log('DNS Names:', dnsNames);
    console.log('URLs:', urls);

    // Scan IPs using VirusTotal API
    ips.forEach(ip => {
        scanUrlWithVirusTotal(ip, "ip");
    });
    
    // Scan domains using VirusTotal API
    dnsNames.forEach(dnsNames => {
        scanUrlWithVirusTotal(dnsNames, "domain");
    });

    // Scan URLs using VirusTotal API
    urls.forEach(url => {
        scanUrlWithVirusTotal(url, "url");
    });
  };

function run(){
    extractArtifacts();
}

// content.js
const modalHtml = `
  <div id="myModal" class="modal">
    <div class="modal-content">
      <div>
        <span class="close">&times;</span>
      </div>
      <div id="artifacts"></div>
    </div>
  </div>
`;

const modalCss = `
  .artifact-result{
    display: flex;
    justify-content: space-between;
    align-items: center;
    width: 100%;
  }
  #artifacts{
    display: flex;
    flex-direction: column;
    align-items: center;
    padding: 30px;
  }
  .modal {
    display: none;
    position: fixed;
    z-index: 1;
    left: 0;
    top: 0;
    width: 100%;
    height: 100%;
    overflow: auto;
    background-color: rgb(0,0,0);
    background-color: rgba(0,0,0,0.4);
    padding-top: 60px;
  }
  .modal-content {
    background-color: #fefefe;
    margin: 5% auto;
    padding: 20px;
    border: 1px solid #888;
    width: 80%;
    display: flex;
    flex-direction: column;
  }
  .close {
    color: #aaa;
    float: right;
    font-size: 28px;
    font-weight: bold;
  }
  .close:hover,
  .close:focus {
    color: black;
    text-decoration: none;
    cursor: pointer;
  }
`;


// Append the modal HTML and CSS to the document
const styleElement = document.createElement('style');
styleElement.textContent = modalCss;
document.head.appendChild(styleElement);

const modalElement = document.createElement('div');
modalElement.innerHTML = modalHtml;
document.body.appendChild(modalElement);

// Get the modal and elements
const modal = document.getElementById("myModal");
const span = document.getElementsByClassName("close")[0];

// When the user clicks the button, open the modal 
button.addEventListener('click', () => {
  run();
  modal.style.display = "block";
});

// When the user clicks on <span> (x), close the modal
span.onclick = function() {
  modal.style.display = "none";
}

// When the user clicks anywhere outside of the modal, close it
window.onclick = function(event) {
  if (event.target == modal) {
    modal.style.display = "none";
  }
}

// Add click event listener to the button
// button.addEventListener('click', run);