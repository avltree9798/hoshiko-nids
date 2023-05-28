from hoshi import Hoshi
from hoshi.rule import RuleReader
import logging


def main():
    logger = logging.getLogger('Hoshiko-IDS')
    try:
        print('Hoshiko IDS started...')
        rules = RuleReader.read('rules.txt')
        hoshi = Hoshi(rules)
        hoshi.start()
    except (KeyboardInterrupt, SystemExit):
        print('HAHA')
        logger.info('Gracefully shutdown from KeyboardInterrupt')
    except Exception as e:
        logger.info(f'Uncaught exception: {e}')
    finally:
        hoshi.stop()
        hoshi.join()


if __name__ == '__main__':
    main()
