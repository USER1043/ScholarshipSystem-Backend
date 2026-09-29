const MIN_SECRET_LENGTH = 32;

/**
 * Get the JWT signing secret from the environment.
 * Throws instead of falling back to a hardcoded default, so a missing
 * secret can never result in tokens signed with a publicly known key.
 * @returns {string}
 */
const getJwtSecret = () => {
    const secret = process.env.JWT_SECRET;
    if (!secret || secret.length < MIN_SECRET_LENGTH) {
        throw new Error(`JWT_SECRET must be set and at least ${MIN_SECRET_LENGTH} characters long`);
    }
    return secret;
};

// Only HS256 is accepted when verifying (prevents algorithm confusion)
const JWT_ALGORITHMS = ['HS256'];

module.exports = { getJwtSecret, JWT_ALGORITHMS };
