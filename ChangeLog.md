# Trustydns Change Log
### v0.2.1 -- 2021-03-23
  * Make sure all version values match - should probably make this more robust
  * Add missing changes to v0.2.0 log entry
  * Remove 'updatepackages' make target
### v0.2.0 -- 2021-03-21
  * Cross-compiles and runs on Windows
  * Pull request #3 "Use time.Since" from @muesli
  * Set trustydns-proxy default padding option (-p) to false as documented
  * Move to go 1.16 and use go modules with semantic version tagging
    For now I'll retain the 'updatepackages' make target but it's superflous with go modules
### v0.1.0 -- 2019-06-28
  * Initial public release.
