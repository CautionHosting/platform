<!-- SPDX-FileCopyrightText: 2025 Caution SEZC -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->

<template>
  <footer class="site-footer">
    <div class="footer-inner">
      <div class="footer-container">
        <!-- Top Row: Brand and Link Columns -->
        <div class="footer-content">
          <!-- Left: Logo and Description -->
          <div class="footer-brand">
            <a href="https://caution.co" class="footer-logo">
              <img src="/assets/caution-logo-white.svg" alt="Caution logo" />
            </a>
            <p class="footer-description">
              Caution is the verifiable compute platform for deploying, proving,
              and scaling confidential workloads anywhere.
            </p>
            <p class="footer-description footer-description--mobile">
              The verifiable compute platform for deploying, proving, and
              scaling confidential workloads.
            </p>
          </div>

          <!-- Right: Link Columns -->
          <div class="footer-links">
            <div class="footer-column">
              <h3 class="footer-column-title">Platform</h3>
              <a href="https://caution.co/about.html" class="footer-link"
                >About</a
              >
              <a href="/" class="footer-link">Get early access</a>
              <a href="/login" class="footer-link">Log in</a>
            </div>

            <div class="footer-column">
              <h3 class="footer-column-title">Resources</h3>
              <a
                href="https://docs.caution.co/"
                target="_blank"
                rel="noopener noreferrer"
                class="footer-link"
                >Documentation</a
              >
              <a href="https://caution.co/blog.html" class="footer-link"
                >Blog</a
              >
              <a href="https://caution.co/contact.html" class="footer-link"
                >Contact</a
              >
            </div>
          </div>
        </div>

        <!-- Bottom: Copyright and Social -->
        <div class="footer-bottom">
          <p class="footer-copyright">
            © 2025 Caution SEZC. All rights reserved.
          </p>
          <div class="footer-social">
            <a
              href="https://codeberg.org/Caution/"
              target="_blank"
              rel="noopener noreferrer"
              aria-label="Git repository"
              title="Access source code"
              class="footer-social-link"
            >
              <svg
                xmlns="http://www.w3.org/2000/svg"
                width="20"
                height="20"
                viewBox="0 0 92 92"
                fill="currentColor"
              >
                <path
                  d="M90.156 41.965 50.036 1.848a5.918 5.918 0 0 0-8.372 0l-8.328 8.332 10.566 10.566a7.03 7.03 0 0 1 7.23 1.684 7.034 7.034 0 0 1 1.669 7.277l10.187 10.184a7.028 7.028 0 0 1 7.278 1.672 7.04 7.04 0 0 1 0 9.957 7.05 7.05 0 0 1-9.965 0 7.044 7.044 0 0 1-1.528-7.66l-9.5-9.497V59.36a7.04 7.04 0 0 1 1.86 11.29 7.04 7.04 0 0 1-9.957 0 7.04 7.04 0 0 1 0-9.958 7.06 7.06 0 0 1 2.304-1.539V33.926a7.049 7.049 0 0 1-3.82-9.234L29.242 14.272 1.73 41.777a5.925 5.925 0 0 0 0 8.371L41.852 90.27a5.925 5.925 0 0 0 8.37 0l39.934-39.934a5.925 5.925 0 0 0 0-8.371"
                />
              </svg>
            </a>
            <a
              href="https://mastodon.social/@caution"
              target="_blank"
              rel="noopener noreferrer"
              aria-label="Mastodon"
              title="Follow on Mastodon"
              class="footer-social-link"
            >
              <svg
                xmlns="http://www.w3.org/2000/svg"
                width="20"
                height="20"
                viewBox="0 0 74 79"
                fill="currentColor"
              >
                <path
                  d="M73.7014 17.9592C72.5616 9.62034 65.1774 3.04876 56.424 1.77536C54.9472 1.56019 49.3517 0.7771 36.3901 0.7771H36.2933C23.3281 0.7771 20.5465 1.56019 19.0697 1.77536C10.56 3.01348 2.78877 8.91838 0.903306 17.356C-0.00357857 21.5113 -0.100361 26.1181 0.068112 30.3439C0.308275 36.404 0.354874 42.4535 0.91406 48.489C1.30064 52.498 1.97502 56.4751 2.93215 60.3905C4.72441 67.6217 11.9795 73.6395 19.0876 76.0945C26.6979 78.6548 34.8821 79.0799 42.724 77.3221C43.5866 77.1245 44.4398 76.8953 45.2833 76.6342C47.1867 76.0381 49.4199 75.3714 51.0616 74.2003C51.0841 74.1839 51.1026 74.1627 51.1156 74.1382C51.1286 74.1138 51.1359 74.0868 51.1368 74.0592V68.2108C51.1364 68.185 51.1302 68.1596 51.1185 68.1365C51.1069 68.1134 51.0902 68.0932 51.0695 68.0773C51.0489 68.0614 51.0249 68.0503 50.9994 68.0447C50.9738 68.0391 50.9473 68.0392 50.9218 68.045C45.8976 69.226 40.7491 69.818 35.5836 69.8087C26.694 69.8087 24.3031 65.6569 23.6184 63.9285C23.0681 62.4347 22.7186 60.8764 22.5789 59.2934C22.5775 59.2669 22.5825 59.2403 22.5934 59.216C22.6043 59.1916 22.621 59.1702 22.6419 59.1533C22.6629 59.1365 22.6876 59.1248 22.714 59.1191C22.7404 59.1134 22.7678 59.1139 22.794 59.1206C27.7345 60.2936 32.799 60.8856 37.8813 60.8843C39.1036 60.8843 40.3223 60.8843 41.5447 60.8526C46.6562 60.7115 52.0437 60.454 57.0728 59.4874C57.1983 59.4628 57.3237 59.4416 57.4313 59.4098C65.3638 57.9107 72.9128 53.2051 73.6799 41.2895C73.7086 40.8204 73.7803 36.3758 73.7803 35.889C73.7839 34.2347 74.3216 24.1533 73.7014 17.9592ZM61.4925 47.6918H53.1514V27.5855C53.1514 23.3526 51.3591 21.1938 47.7136 21.1938C43.7061 21.1938 41.6988 23.7476 41.6988 28.7919V39.7974H33.4078V28.7919C33.4078 23.7476 31.3969 21.1938 27.3894 21.1938C23.7654 21.1938 21.9552 23.3526 21.9516 27.5855V47.6918H13.6176V26.9752C13.6176 22.7423 14.7157 19.3795 16.9118 16.8868C19.1772 14.4 22.1488 13.1231 25.8373 13.1231C30.1064 13.1231 33.3325 14.7386 35.4832 17.9662L37.5587 21.3949L39.6377 17.9662C41.7884 14.7386 45.0145 13.1231 49.2765 13.1231C52.9614 13.1231 55.9329 14.4 58.2055 16.8868C60.4017 19.3772 61.4997 22.74 61.4997 26.9752L61.4925 47.6918Z"
                />
              </svg>
            </a>
          </div>
        </div>
      </div>
    </div>
  </footer>
</template>

<script>
export default {
  name: "SiteFooter",
  emits: ["login"],
};
</script>
