import requests
from urllib import parse

#Задание 1
url = "https://jsonplaceholder.typicode.com/posts"

result = requests.get(url).json()[0:6]

for n, i in enumerate(result):
    print(f'post {n}')
    print('title: ', i['title'])
    print('body: ', i['body'])




#Задание 2
my_api = '7af4b8f48584fff59a082527e751def0'
country = input('Введите название города на английском: ')
url = 'http://api.openweathermap.org/data/2.5/weather'





result = requests.get(url,
                      params={'q': country,
                              'units': 'metric',
                              'lang': 'ru',
                              'APPID': my_api}).json()

temperature = result['main']['temp']
description = result['weather'][0]['description']
name = result['name']
print(f'В городе {name} температура {temperature} градуса, Описание: {description}')



