---
#layout: post
#title:  "Home"
#categories: hackthebox
#tags: [easy, privesc, reverse shell]
---

<h2>About the blog</h2>
* * *
This blog is about it-security, especially CTFs on <a href="https://hackthebox.eu">Hack the box</a>.<br> 
First and foremost, I publish my writeups here for my own documentation purposes.
* * *
<br>
<h2>About me</h2>
* * * 
Data Engineer - IT-Security Enthusiast<br>
[atm-infosec@protonmail.com](mailto:atm-infosec@protonmail.com)
<script src='https://www.hackthebox.eu/badge/113167'></script>
* * * 
<br>
<h2>Posts</h2>
* * *
<div class="container">
{% for category in site.categories %}
    <h3>{{ category[0] }}</h3>
    <ul>
        {% for post in category[1] %}
            <li><a href="{{ post.url }}">{{ post.title }}</a></li>
        {% endfor %}
    </ul>
{% endfor %}
</div>