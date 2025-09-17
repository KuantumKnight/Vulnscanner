// Hardcoded secret - Critical
const API_TOKEN = "sk-1234567890abcdef1234567890abcdef";

function vulnerableFunction(userInput) {
    // SQL Injection - High
    const query = "SELECT * FROM users WHERE username = '" + userInput + "'";
    db.query(query);
    
    // XSS - High
    document.getElementById('output').innerHTML = userInput;
    
    // Command Injection - Critical
    const { exec } = require('child_process');
    exec('ls ' + userInput);
    
    // Path Traversal - High
    const fs = require('fs');
    fs.readFile('../../etc/passwd', 'utf8');
    
    // Weak Crypto - Medium
    const crypto = require('crypto');
    const hash = crypto.createHash('md5').update(userInput).digest('hex');
    
    return hash;
}

// Dangerous eval usage - High
function processData(data) {
    return eval(data);
}

// Debug code in production - Medium
console.log("Debug: " + userInput);