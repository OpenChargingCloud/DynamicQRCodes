
import { generateTOTPs } from './TOTP.js';


// Set current date and time of the timestamp picker!
const now     = new Date();
const year    = now.getFullYear();
const month   = String(now.getMonth()+1).padStart(2, '0');
const day     = String(now.getDate()).   padStart(2, '0');
const hours   = String(now.getHours()).  padStart(2, '0');
const minutes = String(now.getMinutes()).padStart(2, '0');
const seconds = String(now.getSeconds()).padStart(2, '0');

const formattedDateTime = `${year}-${month}-${day}T${hours}:${minutes}:${seconds}`;
document.getElementById('timestamp').value = formattedDateTime;



function replaceTemplate(template, key, value) {
    const regex = new RegExp(`{${key}}`, 'g');
    return template.replace(regex, value);
}



// Handle 'generateTOTPs'-button
document.getElementById('totpForm').addEventListener('submit', async function(event)
{

    event.preventDefault();

    const timestamp    = document.getElementById('timestamp').   value;
    const urlTemplate  = document.getElementById('urlTemplate'). value;
    const evseId       = document.getElementById('evseId').      value;
    const sharedSecret = document.getElementById('sharedSecret').value;
    const validityTime = document.getElementById('validityTime').value;
    const totpLength   = document.getElementById('totpLength').  value;
    const alphabet     = document.getElementById('alphabet').    value;

    const qrCodeDiv    = document.getElementById('qrCode');
    const qrCodeURL    = document.getElementById('qrCodeURL');

    try
    {

        const result = await generateTOTPs(
                           sharedSecret,
                           validityTime ? parseInt(validityTime) : undefined,
                           totpLength   ? parseInt(totpLength)   : undefined,
                           alphabet     ? alphabet               : undefined,
                           timestamp    ? parseInt(timestamp)    : undefined
                       );

        document.getElementById('totpResult').textContent = JSON.stringify(result, null, 2);


        let url = urlTemplate;
        url = replaceTemplate(url, 'evseId', evseId);
        url = replaceTemplate(url, 'totp',   result.current);
        // Remove all remaining placeholders
        url = url.replace(/{(\w+)}/g, '');

        var svgDocument = new QRCode({
                              msg: url,
                              dim: 256,
                              pad: 0,
                              mtx: -1,
                              ecl: "L",
                              ecb: 1,
                              pal: ["#0"],
                              vrb: 0
                          });

        while (qrCodeDiv.firstChild)
            qrCodeDiv.removeChild(qrCodeDiv.firstChild);

        qrCodeDiv.appendChild(svgDocument);

        qrCodeURL.href      = url;
        qrCodeURL.innerText = url;

    } catch (error) {
        document.getElementById('totpResult').textContent = `Error: ${error.message}`;
    }

});


async function main() {
    try
    {

        const result = await generateTOTPs(
                            'secure!Charging!',
                            60,
                            undefined,
                            undefined,
                            1716423785
                        );

        if (result.previous      == 'nTdkiuG6yUyg' &&
            result.current       == 'XJZr0L1DGKn0' &&
            result.next          == 'ft0ONZ62MdMj' &&
            result.remainingTime == 55)
        {
            document.getElementById('testResults').innerHTML = '<div style="color: green">ok!</div>';
        }
        else
            document.getElementById('testResults').innerHTML = '<div style="color: red">failed!</div>';


        // Set a random shared secret
        let   sharedSecret = "";
        const characters   = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_+!$%&/()=?@#*';

        for (let i = 0; i < 16; i++)
            sharedSecret += characters.charAt(Math.floor(Math.random() * characters.length));

        document.getElementById('sharedSecret').value = sharedSecret;


    } catch (error) {
        document.getElementById('testResults').innerHTML = `Error: ${error.message}`;
    }
}

document.addEventListener('DOMContentLoaded', main);
