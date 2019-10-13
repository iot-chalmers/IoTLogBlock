docker logs -f  $(docker ps -a | awk 'NR==2 {print $1; exit}')
