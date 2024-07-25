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


// Functions
// Get the summary of Domain Analysis
function extractImportantInfoForDomain(data) {
    const attributes = data.data.attributes;
  
    // Extract analysis stats
    const analysisStats = attributes.last_analysis_stats;
    const maliciousCount = analysisStats.malicious;
    const suspiciousCount = analysisStats.suspicious;
    const harmlessCount = analysisStats.harmless;
  
    // Extract reputation
    const reputation = attributes.reputation;
  
    // Extract categories
    const categories = attributes.categories;
  
    // Extract registrar
    const registrar = attributes.registrar;
  
    // Prepare a summary
    const summary = {
      maliciousCount,
      suspiciousCount,
      harmlessCount,
      reputation,
    //   categories,
    //   registrar
    };
  
    return summary;
  }

// Get the summary of IP Analysis
function extractImportantInfoForIP(data) {
    const attributes = data.data.attributes;

    // Extract analysis stats
    const analysisStats = attributes.last_analysis_stats;
    const maliciousCount = analysisStats.malicious;
    const suspiciousCount = analysisStats.suspicious;
    const harmlessCount = analysisStats.harmless;

    // Extract reputation
    const reputation = attributes.reputation;

    // Extract country and ASN
    const country = attributes.country;
    const asn = attributes.asn;

    // Extract network information
    const network = attributes.network;

    // Extract AS owner (registrar information)
    const asOwner = attributes.as_owner;

    // Prepare a summary
    const summary = {
        maliciousCount,
        suspiciousCount,
        harmlessCount,
        reputation,
        country,
        asn,
        network,
        asOwner
    };

    return summary;
}

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

// Scan URL... Handled differently than the other artifacts
function scanUrlWithVirusTotal(url){
    // only for URLs, because they are handled differently
    const requestURL = "https://www.virustotal.com/api/v3/urls";
    const body = {
        url: url
    }

    chrome.runtime.sendMessage({ action: "fetchData", url: requestURL, method: 'POST', contentType: "multipart/form-data", body: body}, (response) => {
        // TODO: complete...
    });
}

// Scan IPs and Domains
function scanWithVirusTotal(identifier, type) {
    // IPs -> https://www.virustotal.com/api/v3/ip_addresses/{ip}
    // Domains -> https://www.virustotal.com/api/v3/domains/{domain}

    var endpoints = {
        "ip":`https://www.virustotal.com/api/v3/ip_addresses/${identifier}`,
        "domain":`https://www.virustotal.com/api/v3/domains/${identifier}`
    }

    var url = endpoints[type];
    chrome.runtime.sendMessage({ action: "fetchData", url: url, method: 'GET' }, (response) => {
        if (response.data.data) {
        // get the element that holds the results
        const artifactsResults = document.getElementById("artifacts");
        
        let summary = {};
        if(type === "domain"){
            summary = extractImportantInfoForDomain(response.data);
        }
        if(type === "ip"){
            summary = extractImportantInfoForIP(response.data);
        }

        const newResult = `<div class="artifact-result">
                                <div style="min-width: 150px;">${identifier}</div>
                                <div id=${identifier} class="results-container"></div>
                            </div>`
        artifactsResults.innerHTML += newResult;
        const results = document.getElementById(identifier);
        for (let key in summary) {
            if (summary.hasOwnProperty(key)) { // to filter out properties from the prototype chain
              results.innerHTML += `
              <div class='result-card'>
                <div class='result-card-key'>${key}</div>
                <div class='result-card-value'>${summary[key]}</div>
              </div>
              `;
            }
        }
        } else {
          console.error('Error:', response.data.error.message);
        }
      });
}

// To extract the data we will check
function extractArtifacts() {
    const htmlContent = document.documentElement.outerHTML;
    const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
    const ipRegex4 = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
    const dnsRegex = /\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,6}\b/g;
    const urlRegex = /https?:\/\/[^\s"'>]+/g;



    // Extract artifacts using the regular expressions
    const emails = htmlContent.match(emailRegex) || [];
    const ips = htmlContent.match(ipRegex4) || [];
    const dnsNames = htmlContent.match(dnsRegex) || [];
    const urls = htmlContent.match(urlRegex) || [];

    // Log the extracted artifacts to the console
    // console.log('Emails:', emails);
    // console.log('IPs:', ips);
    // console.log('DNS Names:', dnsNames);
    // console.log('URLs:', urls);

    // Scan IPs using VirusTotal API
    ips.forEach(ip => {
        scanWithVirusTotal(ip, "ip");
    });
    
    // Scan domains using VirusTotal API
    dnsNames.forEach(dnsNames => {
        scanWithVirusTotal(dnsNames, "domain");
    });

    // Scan URLs using VirusTotal API
    urls.forEach(url => {
        scanUrlWithVirusTotal(url);
    });
  };

function run(){
    extractArtifacts();
}

// HTML Content
const modalHtml = `
  <div id="myModal" class="modal">
    <div class="modal-content">
      <div class="modal-header">
        <div class="modal-title">
          Asterio
        </div>
        <div>
          <span class="close">&times;</span>
        </div>
      </div>
      <div id="artifacts"></div>
    </div>
  </div>
`;

const modalCss = `
  .modal-title{
    color: rgb(43, 96, 229);
    font-weight: bolder;
    font-size: 30px;
  }
  .modal-header{
    display: flex;
    justify-content: space-between;
    align-items: center;

    padding-top: 10px;
    padding-bottom: 10px;
    padding-left: 20px;
    padding-right: 20px;

    background: rgba(19, 21, 31, 0.75);

    border-radius: 10px;
  }
  .result-card-value{
      background: rgb(43, 96, 229);
      padding: 4px;
      margin-left: 5px;


      padding-top: 5px;
      padding-bottom: 5px;
      padding-right: 10px;
  }
  .result-card-key{
    padding-top: 5px;
    padding-bottom: 5px;
    padding-left: 10px;
  }
  .result-card{
    display: flex;
    justify-content: center;
    align-items: center;
    flex-direction: row;
    border-radius: 10px;
    /* border: 1px solid red; */
    margin-right: 2.5px;
    margin-left: 2.5px;
    margin-bottom: 5px;
    background: rgba(19, 21, 31, 0.75);
    border: 0.7px solid rgb(43, 96, 229);

    overflow:hidden;
  }
  
  .results-container{
    display: flex;
    flex-wrap: wrap;
  }
  .artifact-result{
    display: flex;
    align-items: center;
    justify-content: flex-start;
    width: 100%;
    margin-bottom:10px;
  }
  #artifacts{
    width:100%;
    display: flex;
    flex-direction: column;
    align-items: center;
    padding: 30px;
    box-sizing: border-box;
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
    font-family: Tahoma, sans-serif;
  }
  .modal-content {
    box-shadow: inset 0px -1px 1px var(--muidocs-palette-primaryDark-700);
    background-color: hsla(210, 14%, 7%, 0.7);
    margin: 5% auto;
    border: 1px solid #888;
    width: 80%;
    display: flex;
    flex-direction: column;

    border-radius: 10px;

    color: white;
    overflow: hidden;
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

// Create the button
const button = createDefaultButton();
document.body.appendChild(button);

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