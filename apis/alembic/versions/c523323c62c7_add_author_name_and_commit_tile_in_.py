"""add_author_name_and_commit_tile_in_issue_commit_relation

Revision ID: c523323c62c7
Revises: 34b0f0d7cd47
Create Date: 2021-12-15 13:56:53.187376

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c523323c62c7'
down_revision = '34b0f0d7cd47'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('issue_commit_relation', sa.Column('author_name', sa.String(), nullable=True))
    op.add_column('issue_commit_relation', sa.Column('commit_title', sa.String(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('issue_commit_relation', 'commit_title')
    op.drop_column('issue_commit_relation', 'author_name')
    # ### end Alembic commands ###
