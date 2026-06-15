/* =============================================================
   PhishGuard AI — Settings page logic
   ============================================================= */
(function () {
    'use strict';

    const profileForm = document.getElementById('profile-form');
    const profileBtn = document.getElementById('profile-btn');
    const profileLabel = profileBtn.querySelector('.btn-label');
    const profileSpinner = profileBtn.querySelector('.btn-spinner');
    const usernameInput = document.getElementById('username');
    const emailInput = document.getElementById('email');

    const passwordForm = document.getElementById('password-form');
    const passwordBtn = document.getElementById('password-btn');
    const passwordLabel = passwordBtn.querySelector('.btn-label');
    const passwordSpinner = passwordBtn.querySelector('.btn-spinner');
    const oldPwInput = document.getElementById('old_password');
    const newPwInput = document.getElementById('new_password');
    const confirmPwInput = document.getElementById('confirm_password');

    const logoutBtn = document.getElementById('logout-btn');

    requireAuth().then((user) => {
        if (!user) return;
        usernameInput.value = user.username;
        emailInput.value = user.email;
    });

    profileForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = usernameInput.value.trim();
        const email = emailInput.value.trim();
        if (username.length < 3) {
            showToast('Username must be at least 3 characters.', 'error');
            return;
        }
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            showToast('Please enter a valid email.', 'error');
            return;
        }
        setLoading(profileBtn, profileLabel, profileSpinner, true);
        try {
            const updated = await apiFetch('/api/user/settings', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, email }),
            });
            setUser(updated);
            showToast('Profile updated successfully.', 'success');
        } catch (err) {
            showToast(err.message || 'Could not update profile.', 'error');
        } finally {
            setLoading(profileBtn, profileLabel, profileSpinner, false);
        }
    });

    passwordForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const oldPassword = oldPwInput.value;
        const newPassword = newPwInput.value;
        const confirmPassword = confirmPwInput.value;

        if (newPassword.length < 6) {
            showToast('New password must be at least 6 characters.', 'error');
            return;
        }
        if (newPassword !== confirmPassword) {
            showToast('New passwords do not match.', 'error');
            return;
        }

        setLoading(passwordBtn, passwordLabel, passwordSpinner, true);
        try {
            await apiFetch('/api/auth/change-password', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ old_password: oldPassword, new_password: newPassword }),
            });
            showToast('Password updated successfully.', 'success');
            passwordForm.reset();
        } catch (err) {
            showToast(err.message || 'Could not change password.', 'error');
        } finally {
            setLoading(passwordBtn, passwordLabel, passwordSpinner, false);
        }
    });

    logoutBtn.addEventListener('click', () => {
        clearToken();
        window.location.href = '/login';
    });
})();
