// Functions

// Create and style the button
function createDefaultButton(){
    const button = document.createElement('button');

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

    console.log(url);

    var apiToken = "b045c6c62e5ed61df7ae5db9b6f655d405509cebb05f19dd77dd947a007fbeb6";

    fetch(url, {
        method: 'GET',
        headers: {
            'Authorization': `Bearer ${apiToken}`, // Adjust the header name if necessary
            'Content-Type': 'application/json'
        }
    })
    .then(response => response.json())
    .then(data => {
        console.log(`Scan results for ${url}:`, data);
        alert(`Scan results for ${url}: ${JSON.stringify(data, null, 2)}`);
    })
    .catch(error => {
        console.error('Error scanning URL with VirusTotal:', error);
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

function extractArtifacts() {
    const htmlContent = document.documentElement.outerHTML;
    // const headContent = document.getElementsByTagName('head')[0].innerHTML;
    // const bodyContent = document.getElementsByTagName('body')[0].innerHTML;
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
// Add click event listener to the button
button.addEventListener('click', run);