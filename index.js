const crypto = require('crypto');

module.exports.templateTags = [
  {
    name: 'signature',
    displayName: 'Signature',
    description: 'calculate signature',
    args: [
      {
        displayName: 'Algorithm',
        type: 'enum',
        options: [
          { displayName: 'MD5', value: 'md5' },
          { displayName: 'SHA1', value: 'sha1' },
          { displayName: 'SHA256', value: 'sha256' },
          { displayName: 'SHA512', value: 'sha512' },
        ],
      },
      {
        displayName: 'Digest Encoding',
        description: 'The encoding of the output',
        type: 'enum',
        options: [
          { displayName: 'Hexadecimal', value: 'hex' },
          { displayName: 'Base64', value: 'base64' },
        ],
      },
      {
        displayName: 'Key',
        type: 'string',
        placeholder: 'Signing key',
      }
    ],
    async run(context, algorithm, encoding, key) {
      if (encoding !== 'hex' && encoding !== 'latin1' && encoding !== 'base64') {
        throw new Error(`Invalid encoding ${encoding}. Choices are hex, latin1, base64`);
      }

      const request = await context.util.models.request.getById(context.meta.requestId);

      const hmac = crypto.createHmac(algorithm, key);
      hmac.update(request.body.text || '', 'utf8');
      return hmac.digest(encoding);
    },
  },
];
