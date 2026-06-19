const fs = require('fs');
let text = fs.readFileSync('deployments/m4-deploy.sh', 'utf8');
text = text.replace(/echo "  ASP=\\$ASP"/, 'echo "  VEIL_CORE=$VEIL_CORE"\necho "  AMM_POOL=$AMM_POOL"\necho "  ASP=$ASP"');
fs.writeFileSync('deployments/m4-deploy.sh', text);
