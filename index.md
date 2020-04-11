---
#layout: post
#title:  "Home"
#categories: hackthebox
#tags: [easy, privesc, reverse shell]
---

<h2>Recent Articles</h2>
* * *
<ul>
  {% for post in site.posts limit:5 %}
    <li>
      <a href="{{ post.url }}">{{ post.title }}</a>
    </li>
  {% endfor %}
</ul>
* * *
<br>
<h2>About me</h2>
* * * 
Data Engineer - IT-Security Enthusiast
<script src='https://www.hackthebox.eu/badge/113167'></script>
* * * 
<br>
<h2>About the blog</h2>
* * *
This blog is about it-security, especially CTFs on <a href="https://hackthebox.eu">Hack the box</a>.<br> 
First and foremost, I publish my writeups here for my own documentation purposes.
* * *