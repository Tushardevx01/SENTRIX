import mongoose from 'mongoose';
import readline from 'node:readline';
import { env } from '../config/index.js';
import { UserModel } from '../models/User.js';
import { hashPassword } from '../utils/auth.js';

interface ProvisioningArgs {
  email?: string;
  password?: string;
  force?: boolean;
}

function parseCliArgs(): ProvisioningArgs {
  const args = process.argv.slice(2);
  const result: ProvisioningArgs = {};

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--email' && args[i + 1]) {
      result.email = args[++i];
    } else if (args[i] === '--password' && args[i + 1]) {
      result.password = args[++i];
    } else if (args[i] === '--force') {
      result.force = true;
    }
  }

  // Fallback to secure environment variables if CLI args are omitted
  if (!result.email && process.env.ADMIN_EMAIL) {
    result.email = process.env.ADMIN_EMAIL;
  }
  if (!result.password && process.env.ADMIN_PASSWORD) {
    result.password = process.env.ADMIN_PASSWORD;
    // Wipe sensitive credential from environment memory immediately
    delete process.env.ADMIN_PASSWORD;
  }

  return result;
}

/**
 * Interactively prompts for masked password input in a terminal to avoid plaintext exposure in ps/bash history.
 */
async function promptMaskedPassword(promptText: string): Promise<string> {
  return new Promise((resolve) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });

    const stdin = process.stdin;
    process.stdout.write(promptText);

    let password = '';
    const onData = (char: Buffer) => {
      const str = char.toString('utf8');
      for (const ch of str) {
        if (ch === '\n' || ch === '\r' || ch === '\u0004') {
          stdin.removeListener('data', onData);
          if (stdin.isTTY) stdin.setRawMode(false);
          process.stdout.write('\n');
          rl.close();
          return resolve(password);
        } else if (ch === '\u0003') {
          process.exit(1);
        } else if (ch === '\u007f' || ch === '\b') {
          if (password.length > 0) {
            password = password.slice(0, -1);
            process.stdout.write('\b \b');
          }
        } else {
          password += ch;
          process.stdout.write('*');
        }
      }
    };

    if (stdin.isTTY) {
      stdin.setRawMode(true);
      stdin.resume();
      stdin.on('data', onData);
    } else {
      rl.question('', (ans) => {
        rl.close();
        resolve(ans.trim());
      });
    }
  });
}

/**
 * Interactively prompts for input text in a terminal.
 */
async function promptText(promptMessage: string): Promise<string> {
  return new Promise((resolve) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });
    rl.question(promptMessage, (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

export async function provisionAdminAccount(options?: ProvisioningArgs): Promise<{ success: boolean; message: string }> {
  const args = options || parseCliArgs();

  const email = args.email?.toLowerCase().trim();
  const password = args.password;

  if (!email || !email.includes('@') || !email.includes('.')) {
    return {
      success: false,
      message: 'Invalid or missing administrator email address. Provide via --email or ADMIN_EMAIL.',
    };
  }

  if (!password || password.length < 12) {
    return {
      success: false,
      message: 'Administrator password must be at least 12 characters long. Provide via --password or ADMIN_PASSWORD.',
    };
  }

  if (password.length > 128) {
    return {
      success: false,
      message: 'Administrator password exceeds maximum length of 128 characters.',
    };
  }

  // Reject commonly used insecure default passwords
  const forbiddenDefaults = ['admin', 'admin123', 'password', 'password123', '123456789012', 'administrator'];
  if (forbiddenDefaults.includes(password.toLowerCase())) {
    return {
      success: false,
      message: 'Insecure default passwords are prohibited for administrator accounts.',
    };
  }

  const existingUser = await UserModel.findOne({ email }).select('+passwordHash');

  if (existingUser) {
    if (existingUser.role === 'admin') {
      if (args.force) {
        // Safe credential update if explicitly forced
        existingUser.passwordHash = await hashPassword(password);
        existingUser.roleVersion = (existingUser.roleVersion || 1) + 1;
        await existingUser.save();
        console.log(`[AUDIT] Administrator account '${email}' password updated and roleVersion incremented.`);
        return {
          success: true,
          message: `Administrator account '${email}' updated successfully.`,
        };
      }

      console.log(`[AUDIT] Administrator account '${email}' already exists. Idempotent check passed; no changes applied.`);
      return {
        success: true,
        message: `Administrator account '${email}' already exists. Use --force to update credentials.`,
      };
    }

    // Existing user elevated to admin
    existingUser.role = 'admin';
    existingUser.roleVersion = (existingUser.roleVersion || 1) + 1;
    if (args.force) {
      existingUser.passwordHash = await hashPassword(password);
    }
    await existingUser.save();
    console.log(`[AUDIT] Existing user account '${email}' promoted to role 'admin' with roleVersion ${existingUser.roleVersion}.`);
    return {
      success: true,
      message: `Account '${email}' promoted to administrator.`,
    };
  }

  // Create fresh administrator with concurrency safety against duplicate key race
  try {
    const passwordHash = await hashPassword(password);
    const admin = await UserModel.create({
      email,
      passwordHash,
      role: 'admin',
      roleVersion: 1,
    });

    console.log(`[AUDIT] Administrator account provisioned successfully: ID=${admin._id.toString()}, email='${email}', role='admin', roleVersion=1`);
    return {
      success: true,
      message: `Administrator account '${email}' provisioned successfully.`,
    };
  } catch (err: any) {
    if (err.code === 11000) {
      return {
        success: true,
        message: `Administrator account '${email}' was already provisioned concurrently.`,
      };
    }
    throw err;
  }
}

async function main() {
  const args = parseCliArgs();

  // If running interactively and credentials not supplied, prompt operator securely
  if (process.stdin.isTTY) {
    if (!args.email) {
      args.email = await promptText('Enter administrator email address: ');
    }
    if (!args.password) {
      args.password = await promptMaskedPassword('Enter administrator password (hidden): ');
    }
  }

  console.log('[SENTRIX Admin Provisioner] Connecting to MongoDB...');
  await mongoose.connect(env.MONGODB_URI, {
    serverSelectionTimeoutMS: 5000,
    autoIndex: false,
  });

  try {
    const result = await provisionAdminAccount(args);
    console.log(`[SENTRIX Admin Provisioner] Result: ${result.message}`);
    process.exit(result.success ? 0 : 1);
  } catch (error: any) {
    console.error('[SENTRIX Admin Provisioner] Fatal error during provisioning:', error.message);
    process.exit(1);
  } finally {
    try {
      await mongoose.disconnect();
    } catch {
      // Disconnect cleanup complete
    }
  }
}

// Execute when run directly as CLI entrypoint
if (process.argv[1]?.endsWith('createAdmin.ts') || process.argv[1]?.endsWith('createAdmin.js')) {
  main().catch((err) => {
    console.error('Fatal initialization error:', err);
    process.exit(1);
  });
}
