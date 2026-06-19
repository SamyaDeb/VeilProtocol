import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';

function getEnv(filePath) {
    const content = fs.readFileSync(filePath, 'utf8');
    const env = {};
    content.split('\n').forEach(line => {
        if (line.trim() && !line.startsWith('#')) {
            const [key, ...val] = line.split('=');
            env[key.trim()] = val.join('=').trim().replace(/^"|"$/g, '');
        }
    });
    return env;
}

function runCmd(cmd) {
    console.log(`Running: ${cmd}`);
    execSync(cmd, { stdio: 'inherit' });
}

async function main() {
    // 1. Generate init args
    console.log('Generating init args...');
    execSync('node deployments/gen-init-args.js > deployments/init.env');
    const initArgs = getEnv('deployments/init.env');
    const netEnv = getEnv('deployments/testnet.env');

    const DEPLOYER = 'deployer'; // identity we generated
    const VEIL_CORE = netEnv.VEIL_CORE;
    const ASP = netEnv.ASP;
    const ADMIN = netEnv.ADMIN;
    const RPC = netEnv.SOROBAN_RPC;
    const PASSPHRASE = netEnv.PASSPHRASE;

    const baseCmd = `stellar contract invoke --rpc-url "${RPC}" --network-passphrase "${PASSPHRASE}" --source "${DEPLOYER}" --fee 1000000`;

    console.log('--- Initializing ASP ---');
    // asp.initialize(operator, approved_root, blocked_root)
    runCmd(`${baseCmd} --id ${ASP} -- initialize --operator ${ADMIN} --approved_root ${initArgs.APPROVED_ROOT} --blocked_root ${initArgs.BLOCKED_ROOT}`);
    
    // asp.update_approved(operator, new_root, _attest)
    runCmd(`${baseCmd} --id ${ASP} -- update_approved --op ${ADMIN} --new_root ${initArgs.APPROVED_ROOT} --attest 00`);

    // asp.update_blocked(operator, new_root, _attest)
    runCmd(`${baseCmd} --id ${ASP} -- update_blocked --op ${ADMIN} --new_root ${initArgs.BLOCKED_ROOT} --attest 00`);

    console.log('--- Initializing Veil Core ---');
    // veil_core.initialize(admin)
    runCmd(`${baseCmd} --id ${VEIL_CORE} -- initialize --admin ${ADMIN}`);

    // veil_core.set_auditor_pubkey(admin, pk)
    runCmd(`${baseCmd} --id ${VEIL_CORE} -- set_auditor_pubkey --admin ${ADMIN} --pk ${initArgs.AUDITOR_PK}`);

    // veil_core.init_vk(admin, vk_id, vk_bytes)
    const vkHex = fs.readFileSync('circuit-keys/dev/vk_deposit.bin').toString('hex');
    runCmd(`${baseCmd} --id ${VEIL_CORE} -- init_vk --admin ${ADMIN} --vk_id '{"Deposit":[]}' --vk_bytes ${vkHex}`);

    const transferVkHex = fs.readFileSync('circuit-keys/dev/vk_transfer.bin').toString('hex');
    runCmd(`${baseCmd} --id ${VEIL_CORE} -- init_vk --admin ${ADMIN} --vk_id '{"Transfer":[]}' --vk_bytes ${transferVkHex}`);

    const addLiquidityVkHex = fs.readFileSync('circuit-keys/dev/vk_add_liquidity.bin').toString('hex');
    runCmd(`${baseCmd} --id ${VEIL_CORE} -- init_vk --admin ${ADMIN} --vk_id '{"AddLiquidity":[]}' --vk_bytes ${addLiquidityVkHex}`);

    const removeLiquidityVkHex = fs.readFileSync('circuit-keys/dev/vk_remove_liquidity.bin').toString('hex');
    runCmd(`${baseCmd} --id ${VEIL_CORE} -- init_vk --admin ${ADMIN} --vk_id '{"RemoveLiquidity":[]}' --vk_bytes ${removeLiquidityVkHex}`);

    console.log('Init completed successfully.');
}

main().catch(console.error);
