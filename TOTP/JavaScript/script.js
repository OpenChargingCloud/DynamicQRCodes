import { generateTOTPs } from './TOTP.js';

document.getElementById('totpForm').addEventListener('submit', async function(event) {
    event.preventDefault();

    const sharedSecret = document.getElementById('sharedSecret').value;
    const validityTime = document.getElementById('validityTime').value;
    const totpLength = document.getElementById('totpLength').value;
    const alphabet = document.getElementById('alphabet').value;
    const timestamp = document.getElementById('timestamp').value;

    try
    {

        const result = generateTOTPs(
            sharedSecret,
            validityTime ? parseInt(validityTime) : undefined,
            totpLength ? parseInt(totpLength) : undefined,
            alphabet ? alphabet : undefined,
            timestamp ? parseInt(timestamp) : undefined
        );

        document.getElementById('totpResult').textContent = JSON.stringify(result, null, 2);

    } catch (error) {
        document.getElementById('totpResult').textContent = `Error: ${error.message}`;
    }

});
