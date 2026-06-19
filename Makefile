-include ./source.mk
-include ./parser/source.mk

.DEFAULT_GOAL := all

NAME	=	ft_nmap

CC		=	gcc
CFLAGS	=	-Wall -Wextra -Werror
LDFLAGS	= 	-lpcap -lpthread

BUILD_DIR	=	build
OBJS_DIR	=	$(BUILD_DIR)/objects

SRCS		=	$(addprefix parser/, $(PARSER_SRCS)) $(addprefix src/, $(MAIN_SRCS))
OBJS_PATH	=	$(patsubst %.c,$(OBJS_DIR)/%.o,$(SRCS))

PARSER_DIR	=	parser

RED			=	\033[1;31m
GREEN		=	\033[1;32m
YELLOW		=	\033[1;33m
BLUE		=	\033[1;34m
CYAN		=	\033[1;36m
RESET		=	\033[0m
UP			=	\033[A
CUT			=	\033[K

TOTAL_FILES			=	$(words $(SRCS))

$(OBJS_DIR)/%.o: %.c
	@mkdir -p $(@D)
	@if [ ! -f .count ]; then echo 0 > .count; fi
	@COUNT=$$(($$(cat .count) + 1)); \
	echo $$COUNT > .count; \
	PERCENT=$$(($$COUNT * 100 / $(TOTAL_FILES))); \
	printf "$(CUT)$(RESET)[$(YELLOW)%3d%%$(RESET)] 🔓 Breaching node: %s\n" $$PERCENT $(notdir $<)
	@$(CC) $(CFLAGS) -I include -I $(PARSER_DIR) -c $< -o $@
	@printf "$(UP)"

$(NAME): $(OBJS_PATH)
	@printf "$(RESET)[$(GREEN)DONE$(RESET)] 🛰️ $(CYAN)Establishing uplink...$(RESET)$(CUT)\n"
	@$(CC) $(CFLAGS) $(OBJS_PATH) $(LDFLAGS) -o $(NAME)
	@rm -f .count
	@printf "$(RESET)[$(GREEN)DONE$(RESET)] 💀 $(BLUE)Root access granted — $(NAME) is online.$(RESET)$(CUT)\n"

all:
	@if $(MAKE) -q $(NAME) --no-print-directory; then \
		printf "$(RESET)[$(GREEN)DONE$(RESET)] 🛰️ $(BLUE)Connection already established. We're in.$(RESET)\n"; \
	else \
		$(MAKE) $(NAME) --no-print-directory; \
	fi

clean:
	@rm -f .count
	@rm -rf $(OBJS_DIR)
	@printf "$(RESET)[$(GREEN)DONE$(RESET)] 🧹 $(YELLOW)Wiping the logs.$(RESET)\n"

fclean: clean
	@rm -rf $(BUILD_DIR) $(NAME)
	@printf "$(RESET)[$(GREEN)DONE$(RESET)] 🔥 $(RED)Burning the evidence. No trace left.$(RESET)\n"

re: fclean all

.PHONY: all clean fclean re
