# slither-checker

- Простой HTTP сервер на Python, обвязка для вызова утилиты [slither](https://github.com/crytic/slither) для исходников контрактов, полученных с Etherscan
- В конфиге `scores.yaml` описаны правила получения `security score` из репорта `slither`: таблица соответсвия `confidence+imapct` в баллы + коэффициенты для отдельных уязвимостей (для того, чтобы можно было вручную "подтюнить" конвертацию)

## Как запустить
```bash
pipenv install ; pipenv run python extractor.py
```

## endpoints
- Сервер принимает `POST` запрос по порту `7777` (hardcoded for now), в теле которого - json, полученный из Etherscan (мы его предварительно пишем в базу). Ответ - json, состоящий из репорта slither + посчитанный score, либо сообщение об ошибке (нет исходников / не Solidty / ошибка в slither)
