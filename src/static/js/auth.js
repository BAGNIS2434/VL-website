export class Auth {
    static async resetPassword(email) {
        const response = await fetch('/api/auth/reset-password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email })
        });
        return response.ok;
    }

    static async changePassword(currentPassword, newPassword) {
        // ...password change logic...
    }
}
