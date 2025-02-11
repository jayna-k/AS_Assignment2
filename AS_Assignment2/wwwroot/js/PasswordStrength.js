<script>
    const passwordInput = document.querySelector('input[name="RModel.Password"]');
    const passwordStrengthBar = document.getElementById('passwordStrengthBar');
    const passwordStrengthText = document.getElementById('passwordStrengthText');

    passwordInput.addEventListener('input', function () {
        const password = passwordInput.value;
    let strength = 'Weak';
    let width = '0%';

    const regexUpper = /[A-Z]/;
    const regexLower = /[a-z]/;
    const regexNumber = /[0-9]/;
    const regexSpecial = /[!@#$%^&*(),.?":{ }|<>]/;

        let strengthScore = 0;

        if (password.length >= 12) {
            strengthScore++;
        }
        if (regexUpper.test(password)) {
            strengthScore++;
        }
        if (regexLower.test(password)) {
            strengthScore++;
        }
        if (regexNumber.test(password)) {
            strengthScore++;
        }
        if (regexSpecial.test(password)) {
            strengthScore++;
        }

        switch (strengthScore) {
            case 0:
        case 1:
        strength = 'Weak';
        width = '0%';
        passwordStrengthBar.className = 'progress-bar weak';
        break;
        case 2:
        strength = 'Medium';
        width = '50%';
        passwordStrengthBar.className = 'progress-bar medium';
        break;
        case 3:
        case 4:
        strength = 'Strong';
        width = '100%';
        passwordStrengthBar.className = 'progress-bar strong';
        break;
        default:
        strength = 'Weak';
        width = '0%';
        passwordStrengthBar.className = 'progress-bar weak';
        break;
        }

        passwordStrengthBar.style.width = width;
        passwordStrengthText.textContent = `Password strength: ${strength}`;
    });
    </script>