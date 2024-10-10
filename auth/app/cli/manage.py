from asyncio import run
from uuid import UUID

import typer
from db.pg import async_session
from models.role import Role, UserRole
from models.user import User
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession


async def get_user_by_email(db: AsyncSession, email: str) -> UUID:
    result = await db.execute(select(User).where(User.email == email))
    print(result)
    user = result.scalars().first()
    print(f"User is {user}")
    if user:
        return user.id
    return False


async def create_user_by_email(db: AsyncSession, email: str) -> bool:

    username = typer.prompt("Enter username for a new user")
    full_name = f"admin {username}"
    password = typer.prompt(
        f"Enter password for {username}", hide_input=True, confirmation_prompt=True
    )

    user = User(email=email, password=password, username=username, full_name=full_name)
    db.add(user)
    await db.commit()
    await db.refresh(user)
    print(f"{username} has been created.")
    return user.id


async def get_admin_role_by_name(db: AsyncSession) -> UUID:
    result = await db.execute(select(Role).where(Role.name == "admin"))
    admin_role = result.scalars().first()
    if admin_role:
        return admin_role.id


async def create_admin_role(db: AsyncSession) -> UUID:
    admin_role = Role(name="admin")
    db.add(admin_role)
    await db.commit()
    await db.refresh(admin_role)
    print("Роль admin добавлена в базу.")
    return admin_role.id


async def check_if_user_admin(db: AsyncSession, user_id, role_id):
    result = await db.execute(
        select(UserRole).where(UserRole.user_id == user_id, UserRole.role_id == role_id)
    )
    if result.scalars().first():
        return True
    return False


async def add_admin_role_to_user(db: AsyncSession, user_id, role_id):
    user_role = UserRole(user_id=user_id, role_id=role_id)
    db.add(user_role)
    await db.commit()
    await db.refresh(user_role)
    print("User has been granted with admin.")
    return True


async def async_main():
    async with async_session() as db:
        email = typer.prompt("Enter admin email")

        user_id = await get_user_by_email(db, email)

        # Check if user is exist and create it if not
        if user_id:
            print(f"{user_id} is exist")
        else:
            user_id = await create_user_by_email(db, email)

        # Check if admin role is exist and create it if not
        role_id = await get_admin_role_by_name(db)
        print(f"admin role is {role_id}")
        if not role_id:
            role_id = await create_admin_role(db)

        if not await check_if_user_admin(db, user_id, role_id):
            if await add_admin_role_to_user(db, user_id, role_id):
                return True


def main():
    run(async_main())


if __name__ == "__main__":
    typer.run(main)
