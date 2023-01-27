module.exports = {
  extends: ['@commitlint/config-conventional'],
  rules: {
    'body-max-line-length': [2, 'always', [120]],
    'type-enum': [2, 'always', ['chore', 'feat', 'fix']],
    'not-breaking-change': [2, 'always', []],
  },
  plugins: [{
    rules: {
      'not-breaking-change': ({notes}) => [notes.every((n) => n.title != 'BREAKING CHANGE'), 'commit must not be a breaking change']
    }
  }]
}
