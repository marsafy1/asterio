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

document.addEventListener('click', () => {
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
  });
  