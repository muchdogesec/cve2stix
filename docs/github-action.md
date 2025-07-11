## Support for Cloudflare R2 + Github action

We use a Github action to run this script daily to store the bundles generated on Cloudflare R2.

The script runs at 0700 UTC everyday (github servers UTC) using cron:  `"0 7 * * *"`

You can see the action in: `/.github/workflows/daily-r2.yml`.

Essentially the following command is run everyday by the action

```shell
python3 run_cve2stix.py \
	mod \
	--earliest "YESTERDAY (00:00:00)" \
	--latest "YESTERDAY (23:59:59)" \
	--file_time_range 1d
```

The action will store the data in the bucket as follows;

```txt
cve2stix-action-output
└──cve
 	└── 2023-01
	  	└── cve-bundle-2023_01_01-2023_01_02.json
```

If you'd like to run the action in your own repository to create your own data store you will need to do the following;

### Create Cloudflare bucket/keys

First, go to Cloudflare.com and navigate to R2. Create a new bucket called `cve2stix-action-output` (you can change this).

Now you need to create a CloudFlare API keys. For the CloudFlare API Key you create, make sure to set the permissions to `Admin Read & Write`. For security, it is also worth limiting the scope of the key to the bucket `cve2stix-action-output` (defined in the action).

### Set Github vars

Then go to the Github repo, then `repo > settings > secrets and variables > actions > new repository secret`.

![](docs/github-repo-vars.png)

Then choose one of the following options;

Set the following in Github secrets;

```txt
CLOUDFLARE_ACCOUNT_ID=#Get this in Cloudflare R2 UI (it looks like this: https://<ID>.r2.cloudflarestorage.com)
CLOUDFLARE_ACCESS_KEY_ID=#Get this in Cloudflare R2 UI
CLOUDFLARE_ACCESS_KEY_SECRET=#Get this in Cloudflare R2 UI
S3_BUCKET_NAME=cve2stix-action-output
NVD_API_KEY=#Get this from https://nvd.nist.gov/developers/request-an-api-key
```