## About the blog
* * *
This blog is about it-security, especially CTFs on [Hack the Box](https://hackthebox.eu){:target="_blank"}.<br>
First and foremost, I publish my writeups here for my own documentation purposes.
* * *

## About me
* * * 
Data Engineer - IT-Security Enthusiast<br>
[atm-infosec@protonmail.com](mailto:atm-infosec@protonmail.com)
<script src='https://www.hackthebox.eu/badge/113167'></script>
* * * 
## Posts
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