# hc-assets

Public image host for the AwardSpring Help Center. Served by GitHub Pages.

Intercom's Articles API has **no image upload endpoint** — images must be publicly
hosted and referenced by URL in the article body. This repo is that host.

These images are already published publicly in the Help Center, so the repo being
public exposes nothing new.

## The one rule

**Filenames are URLs. Never rename a file that is already referenced by an article.**

A stable path is what makes this cheap: re-uploading a screenshot to the same path
updates every article referencing it **with no API call at all**. Image refreshes
stop needing article writes. Renaming, by contrast, means rewriting every body that
points at the old name.

Names are cut by `ship.mjs` in the HC-Capture repo:

```
PROD_<collection>_<section>_<slug>_<shot-id>[_boxed].png
```

Flat and self-describing on purpose — Intercom flattens filenames on upload, so once
a file leaves its folder the name is all the context there is.

`_boxed` means the annotated variant. For an annotated shot that is the deliverable;
for an un-annotated one the clean master is.

## Publishing

```bash
git add . && git commit -m "..." && git push     # that is the deploy
```

Then, from HC-Capture:

```bash
node image-host.mjs --check    # confirms every URL resolves AND returns an image
```

Run that before any article write. Intercom rejects a missing image with
`unsupported_html: Image not found at URL` and fails the **entire** article write,
not just that image — so one bad URL loses the whole article.
